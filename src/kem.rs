//! RE-KEM: Ring-LWE Key Encapsulation Mechanism with Fujisaki-Okamoto transform.
//!
//! Ported 1:1 from the Python reference (`rekem.py`), parameters
//! n = 512, q = 12289, eta = 8 (NewHope-512 regime, IND-CCA2).
//!
//! Hash usage (must match the reference exactly):
//!   H(pk)   = SHA3-256(pk)
//!   G(m||H) = SHA3-512(m || H(pk))          -> (k_bar, coins)
//!   H(c)    = SHA3-256(ciphertext)
//!   KDF     = SHAKE-256(k_bar || H(c))      -> 32-byte shared secret

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Sha3_256, Sha3_512, Shake256};

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::field::{FieldElement, Q};
use crate::ntt::{NttContext, Poly, N};
use crate::sampling::{cbd_sample, decode_poly, encode_poly, expand_a};

pub const SEED_LEN: usize = 32;
pub const POLY_LEN: usize = 2 * N; // 1024
pub const PK_LEN: usize = SEED_LEN + POLY_LEN; // 1056
pub const SK_LEN: usize = POLY_LEN + PK_LEN + 32 + SEED_LEN; // 2144
pub const CT_LEN: usize = 2 * POLY_LEN; // 2048
pub const SS_LEN: usize = 32;

/// Bits of the 32-byte message, MSB-first (matching NumPy `unpackbits`).
#[inline]
fn msg_bit(msg: &[u8; SEED_LEN], idx: usize) -> u8 {
    let byte = msg[idx / 8];
    (byte >> (7 - (idx % 8))) & 1
}

/// Embeds the 256 message bits into a polynomial with amplitude q/2.
/// Coefficients beyond bit 255 stay zero (the reference zero-pads to `n`).
fn msg_to_poly(msg: &[u8; SEED_LEN]) -> Poly {
    let half = (Q / 2) as u16;
    let mut p = Poly::zero();
    for i in 0..(SEED_LEN * 8) {
        if msg_bit(msg, i) == 1 {
            p.coeffs[i] = FieldElement::from_plain(half);
        }
    }
    p
}

/// Recovers the 256 message bits from the (recentred) coefficients.
///
/// Mirrors `_ct_decode_coefficients`: a coefficient is a 1-bit if its centred
/// magnitude exceeds q/4. Output is packed MSB-first.
fn poly_to_msg(p: &Poly) -> [u8; SEED_LEN] {
    let half_q = (Q / 2) as i32;
    let quarter_q = (Q / 4) as i32;
    let mut out = [0u8; SEED_LEN];

    for i in 0..(SEED_LEN * 8) {
        let v = p.coeffs[i].to_plain() as i32;
        // recentre into (-q/2, q/2]  — branchless form kept explicit below
        let centred = if v > half_q { v - Q as i32 } else { v };
        let abs = if centred < 0 { -centred } else { centred };
        let bit = (abs > quarter_q) as u8;
        out[i / 8] |= bit << (7 - (i % 8));
    }
    out
}

/// Deterministic CPAPKE encryption.
fn pke_encrypt(ctx: &NttContext, pk: &[u8], msg: &[u8; SEED_LEN], coins: &[u8]) -> [u8; CT_LEN] {
    let seed_a = &pk[..SEED_LEN];
    let b = decode_poly(&pk[SEED_LEN..]);
    let a = expand_a(seed_a);

    let r = cbd_sample(coins, 0);
    let e1 = cbd_sample(coins, 1);
    let e2 = cbd_sample(coins, 2);

    let u = ctx.mul(&a, &r).add(&e1);
    let v = ctx.mul(&b, &r).add(&e2).add(&msg_to_poly(msg));

    let mut ct = [0u8; CT_LEN];
    ct[..POLY_LEN].copy_from_slice(&encode_poly(&u));
    ct[POLY_LEN..].copy_from_slice(&encode_poly(&v));
    ct
}

/// Deterministic CPAPKE decryption.
fn pke_decrypt(ctx: &NttContext, s: &Poly, ct: &[u8]) -> [u8; SEED_LEN] {
    let u = decode_poly(&ct[..POLY_LEN]);
    let v = decode_poly(&ct[POLY_LEN..]);
    let w = v.sub(&ctx.mul(&u, s));
    poly_to_msg(&w)
}

fn h_pk(pk: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    Digest::update(&mut h, pk);
    h.finalize().into()
}

fn h_ct(ct: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    Digest::update(&mut h, ct);
    h.finalize().into()
}

fn g_fn(m: &[u8; SEED_LEN], hp: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut h = Sha3_512::new();
    Digest::update(&mut h, m);
    Digest::update(&mut h, hp);
    let out = h.finalize();
    let mut k_bar = [0u8; 32];
    let mut coins = [0u8; 32];
    k_bar.copy_from_slice(&out[..32]);
    coins.copy_from_slice(&out[32..]);
    (k_bar, coins)
}

fn kdf(seed: &[u8; 32], hc: &[u8; 32]) -> [u8; SS_LEN] {
    let mut xof = Shake256::default();
    Update::update(&mut xof, seed);
    Update::update(&mut xof, hc);
    let mut reader = xof.finalize_xof();
    let mut ss = [0u8; SS_LEN];
    reader.read(&mut ss);
    ss
}

/// The RE-KEM instance (holds precomputed NTT tables; cheap to construct once).
pub struct ReKem {
    ctx: NttContext,
}

impl Default for ReKem {
    fn default() -> Self {
        Self::new()
    }
}

impl ReKem {
    pub fn new() -> ReKem {
        ReKem {
            ctx: NttContext::new(),
        }
    }

    /// Deterministic key generation from explicit seeds (for test vectors).
    pub fn keygen_derand(
        &self,
        seed_a: &[u8; SEED_LEN],
        noise_seed: &[u8; SEED_LEN],
        z: &[u8; SEED_LEN],
    ) -> ([u8; PK_LEN], [u8; SK_LEN]) {
        let a = expand_a(seed_a);
        let s = cbd_sample(noise_seed, 0);
        let e = cbd_sample(noise_seed, 1);
        let b = self.ctx.mul(&a, &s).add(&e);

        let mut pk = [0u8; PK_LEN];
        pk[..SEED_LEN].copy_from_slice(seed_a);
        pk[SEED_LEN..].copy_from_slice(&encode_poly(&b));

        let hp = h_pk(&pk);

        let mut sk = [0u8; SK_LEN];
        sk[..POLY_LEN].copy_from_slice(&encode_poly(&s));
        sk[POLY_LEN..POLY_LEN + PK_LEN].copy_from_slice(&pk);
        sk[POLY_LEN + PK_LEN..POLY_LEN + PK_LEN + 32].copy_from_slice(&hp);
        sk[POLY_LEN + PK_LEN + 32..].copy_from_slice(z);

        (pk, sk)
    }

    /// Key generation with fresh randomness.
    #[cfg(feature = "rng")]
    pub fn keygen(&self) -> ([u8; PK_LEN], [u8; SK_LEN]) {
        let mut buf = Zeroizing::new([0u8; 3 * SEED_LEN]);
        getrandom::getrandom(&mut *buf).expect("OS randomness unavailable");
        let mut seed_a = Zeroizing::new([0u8; SEED_LEN]);
        let mut noise_seed = Zeroizing::new([0u8; SEED_LEN]);
        let mut z = Zeroizing::new([0u8; SEED_LEN]);
        seed_a.copy_from_slice(&buf[..32]);
        noise_seed.copy_from_slice(&buf[32..64]);
        z.copy_from_slice(&buf[64..]);
        self.keygen_derand(&seed_a, &noise_seed, &z)
    }

    /// Deterministic encapsulation (explicit message) — for test vectors.
    pub fn encaps_derand(&self, pk: &[u8; PK_LEN], m: &[u8; SEED_LEN]) -> ([u8; CT_LEN], [u8; SS_LEN]) {
        let hp = h_pk(pk);
        // k_bar and the encapsulation coins are secret; wipe them on scope exit.
        let (k_bar, coins) = g_fn(m, &hp);
        let k_bar = Zeroizing::new(k_bar);
        let coins = Zeroizing::new(coins);
        let ct = pke_encrypt(&self.ctx, pk, m, &coins[..]);
        let hc = h_ct(&ct);
        let ss = kdf(&k_bar, &hc);
        (ct, ss)
    }

    /// Encapsulation with fresh randomness.
    #[cfg(feature = "rng")]
    pub fn encaps(&self, pk: &[u8; PK_LEN]) -> ([u8; CT_LEN], [u8; SS_LEN]) {
        let mut m = Zeroizing::new([0u8; SEED_LEN]);
        getrandom::getrandom(&mut *m).expect("OS randomness unavailable");
        self.encaps_derand(pk, &m)
    }

    /// Decapsulation with implicit rejection (never fails; returns a
    /// pseudorandom secret on invalid ciphertexts).
    pub fn decaps(&self, sk: &[u8; SK_LEN], ct: &[u8; CT_LEN]) -> [u8; SS_LEN] {
        let s = decode_poly(&sk[..POLY_LEN]);

        let mut pk = [0u8; PK_LEN];
        pk.copy_from_slice(&sk[POLY_LEN..POLY_LEN + PK_LEN]);

        let mut hp = [0u8; 32];
        hp.copy_from_slice(&sk[POLY_LEN + PK_LEN..POLY_LEN + PK_LEN + 32]);

        let mut z = [0u8; SEED_LEN];
        z.copy_from_slice(&sk[POLY_LEN + PK_LEN + 32..]);

        // 1. candidate plaintext (secret — wiped on exit)
        let m_prime = Zeroizing::new(pke_decrypt(&self.ctx, &s, ct));

        // 2. re-derive the encapsulation coins
        let (k_bar_prime, coins_prime) = g_fn(&m_prime, &hp);
        let k_bar_prime = Zeroizing::new(k_bar_prime);
        let coins_prime = Zeroizing::new(coins_prime);

        // 3. re-encrypt
        let ct_prime = pke_encrypt(&self.ctx, &pk, &m_prime, &coins_prime[..]);

        // 4. constant-time comparison (implicit rejection)
        let fail: u8 = ct.ct_eq(&ct_prime).unwrap_u8() ^ 1;

        // 5. shared secret: success or rejection branch
        let hc = h_ct(ct);
        let ss_success = Zeroizing::new(kdf(&k_bar_prime, &hc));
        let ss_fail = Zeroizing::new(kdf(&z, &hc));

        let mut ss = [0u8; SS_LEN];
        let mask = 0u8.wrapping_sub(fail); // 0xFF if fail, 0x00 otherwise
        for i in 0..SS_LEN {
            ss[i] = (ss_fail[i] & mask) | (ss_success[i] & !mask);
        }
        ss
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_encaps_decaps_roundtrip() {
        let kem = ReKem::new();
        let (pk, sk) = kem.keygen_derand(&[1u8; 32], &[2u8; 32], &[3u8; 32]);
        let (ct, ss_tx) = kem.encaps_derand(&pk, &[4u8; 32]);
        let ss_rx = kem.decaps(&sk, &ct);
        assert_eq!(ss_tx, ss_rx, "shared secrets must match");
    }

    #[test]
    fn lengths_match_reference() {
        let kem = ReKem::new();
        let (pk, sk) = kem.keygen_derand(&[1u8; 32], &[2u8; 32], &[3u8; 32]);
        let (ct, ss) = kem.encaps_derand(&pk, &[4u8; 32]);
        assert_eq!(pk.len(), PK_LEN);
        assert_eq!(sk.len(), SK_LEN);
        assert_eq!(ct.len(), CT_LEN);
        assert_eq!(ss.len(), SS_LEN);
        assert_eq!(PK_LEN, 1056);
        assert_eq!(SK_LEN, 2144);
        assert_eq!(CT_LEN, 2048);
    }

    #[test]
    fn tampered_ciphertext_gives_different_secret() {
        let kem = ReKem::new();
        let (pk, sk) = kem.keygen_derand(&[5u8; 32], &[6u8; 32], &[7u8; 32]);
        let (ct, ss) = kem.encaps_derand(&pk, &[8u8; 32]);

        let mut bad = ct;
        bad[100] ^= 0x01;
        let ss_bad = kem.decaps(&sk, &bad);
        assert_ne!(ss, ss_bad, "tampered ciphertext must not yield the real secret");
    }

    #[test]
    fn wrong_secret_key_gives_different_secret() {
        let kem = ReKem::new();
        let (pk, _sk) = kem.keygen_derand(&[9u8; 32], &[10u8; 32], &[11u8; 32]);
        let (_, other_sk) = kem.keygen_derand(&[12u8; 32], &[13u8; 32], &[14u8; 32]);
        let (ct, ss) = kem.encaps_derand(&pk, &[15u8; 32]);
        let ss_wrong = kem.decaps(&other_sk, &ct);
        assert_ne!(ss, ss_wrong);
    }

    #[test]
    fn deterministic_reproducibility() {
        let kem = ReKem::new();
        let (pk1, sk1) = kem.keygen_derand(&[20u8; 32], &[21u8; 32], &[22u8; 32]);
        let (pk2, sk2) = kem.keygen_derand(&[20u8; 32], &[21u8; 32], &[22u8; 32]);
        assert_eq!(pk1, pk2);
        assert_eq!(sk1, sk2);

        let (ct1, ss1) = kem.encaps_derand(&pk1, &[23u8; 32]);
        let (ct2, ss2) = kem.encaps_derand(&pk2, &[23u8; 32]);
        assert_eq!(ct1, ct2);
        assert_eq!(ss1, ss2);
    }
}
