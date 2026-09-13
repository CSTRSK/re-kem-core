//! RE-KEM: Ring-LWE Key Encapsulation Mechanism with Fujisaki-Okamoto transform.
//!
//! Ported 1:1 from the Python reference (`rekem.py`).
//!
//! Hash usage (must match the reference exactly):
//!   H(pk)   = SHA3-256(pk)
//!   G(m||H) = SHA3-512(m || H(pk))          -> (k_bar, coins)
//!   H(c)    = SHA3-256(ciphertext)
//!   KDF     = SHAKE-256(k_bar || H(c))      -> 32-byte shared secret
//!
//! ## Generic dimensions
//!
//! The KEM is generic over the ring dimension `N` **and** the three byte
//! lengths derived from it. The lengths are separate const parameters because
//! stable Rust does not allow array lengths to use a const parameter in
//! arithmetic (`[u8; 32 + 2 * N]` needs nightly `generic_const_exprs`).
//!
//! The relation between them is not assumed anywhere — it is asserted:
//!
//! ```text
//! PK = 32 + 2N          SK = 2N + PK + 64          CT = 4N
//! ```
//!
//! See [`tests::size_invariants_hold`] and [`KemGeneric::sizes_are_consistent`].
//!
//! ## What is *not* claimed about a second parameter set
//!
//! Adding `n = 1024` does not inherit the NewHope-1024 failure analysis: that
//! work assumes a 4-fold redundant per-bit encoding, whereas this crate uses
//! zero padding (bits occupy the first 256 coefficients at amplitude q/2, the
//! rest stay 0). The failure probability for *this* combination is bounded in
//! `docs/error-probability.md` from the noise model directly, and that bound —
//! not the literature — is the basis for offering the set. Availability is
//! gated on that documented derivation plus byte-level cross-validation against
//! the Python reference at the same dimension.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Sha3_256, Sha3_512, Shake256};

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::field::{FieldElement, Q};
use crate::ntt::{NttContext, Poly};
use crate::sampling::{cbd_sample, decode_poly, encode_poly, expand_a};

/// Seed length in bytes (identical for both parameter sets).
pub const SEED_LEN: usize = crate::params::ACTIVE.seed_len;

// ── Sizes of the compiled-in default set (n = 512) ──
/// Encoded polynomial length: 2 bytes per coefficient.
pub const POLY_LEN: usize = crate::params::ACTIVE.poly_len();
/// Public key: `seed_a || b(x)`.
pub const PK_LEN: usize = crate::params::ACTIVE.pk_len();
/// Secret key: `s(x) || pk || H(pk) || z`.
pub const SK_LEN: usize = crate::params::ACTIVE.sk_len();
/// Ciphertext: `u(x) || v(x)`.
pub const CT_LEN: usize = crate::params::ACTIVE.ct_len();
/// Shared secret length in bytes.
pub const SS_LEN: usize = crate::params::ACTIVE.ss_len;

// ── Sizes of the second parameter set (n = 1024) ──
/// Public key length at `n = 1024`.
pub const PK_LEN_1024: usize = crate::params::LEVEL5_1024.pk_len();
/// Secret key length at `n = 1024`.
pub const SK_LEN_1024: usize = crate::params::LEVEL5_1024.sk_len();
/// Ciphertext length at `n = 1024`.
pub const CT_LEN_1024: usize = crate::params::LEVEL5_1024.ct_len();

/// Bits of the 32-byte message, MSB-first (matching NumPy `unpackbits`).
#[inline]
fn msg_bit(msg: &[u8; SEED_LEN], idx: usize) -> u8 {
    let byte = msg[idx / 8];
    (byte >> (7 - (idx % 8))) & 1
}

/// Embeds the 256 message bits into a polynomial with amplitude q/2.
/// Coefficients beyond bit 255 stay zero (zero padding — see module docs).
///
/// Branchless: the message is secret, so `if bit == 1 { .. }` is not used —
/// the coefficient is simply `half * bit`, a multiplication that LLVM keeps
/// free of data-dependent control flow.
fn msg_to_poly<const N: usize>(msg: &[u8; SEED_LEN]) -> Poly<N> {
    let half = (Q / 2) as u16;
    let mut p = Poly::<N>::zero();
    for i in 0..(SEED_LEN * 8) {
        let bit = msg_bit(msg, i) as u16; // 0 or 1
        p.coeffs[i] = FieldElement::from_plain(half.wrapping_mul(bit));
    }
    p
}

/// Recovers the 256 message bits from the (recentred) coefficients.
///
/// Mirrors `_ct_decode_coefficients`: a coefficient is a 1-bit if its centred
/// magnitude exceeds q/4. Only the first `SEED_LEN*8` coefficients are read —
/// at `n = 1024` the 768 padding coefficients are never consulted, which is
/// exactly why the failure analysis must be redone per dimension rather than
/// inherited.
///
/// Runs on secret material, therefore entirely with bit masks — an `if` here
/// is not guaranteed to become a `cmov`, it is compiler/target/opt-level
/// dependent. Output is packed MSB-first.
fn poly_to_msg<const N: usize>(p: &Poly<N>) -> [u8; SEED_LEN] {
    let half_q = (Q / 2) as i32;
    let quarter_q = (Q / 4) as i32;
    let q = Q as i32;
    let mut out = [0u8; SEED_LEN];

    for i in 0..(SEED_LEN * 8) {
        let v = p.coeffs[i].to_plain() as i32; // in [0, q)

        // recentre: centred = v - q if v > half_q, else v
        // mask = -1 when half_q - v < 0 (i.e. v > half_q), else 0
        let mask = (half_q - v) >> 31;
        let centred = v - (q & mask);

        // branchless abs: abs(x) = (x + sign) ^ sign, sign = x >> 31
        let sign = centred >> 31;
        let abs = (centred + sign) ^ sign;

        // bit = 1 iff abs > quarter_q
        let bit = (((quarter_q - abs) >> 31) & 1) as u8;
        out[i / 8] |= bit << (7 - (i % 8));
    }
    out
}

/// Deterministic CPAPKE encryption. Requires `CT = 4N`.
fn pke_encrypt<const N: usize, const CT: usize>(
    ctx: &NttContext<N>,
    pk: &[u8],
    msg: &[u8; SEED_LEN],
    coins: &[u8],
) -> [u8; CT] {
    debug_assert_eq!(CT, 4 * N, "ciphertext length must be 4N");
    let seed_a = &pk[..SEED_LEN];
    let b = decode_poly::<N>(&pk[SEED_LEN..]);
    let a = expand_a::<N>(seed_a);

    let r = cbd_sample::<N>(coins, 0);
    let e1 = cbd_sample::<N>(coins, 1);
    let e2 = cbd_sample::<N>(coins, 2);

    let u = ctx.mul(&a, &r).add(&e1);
    let v = ctx
        .mul(&b, &r)
        .add(&e2)
        .add(&msg_to_poly::<N>(msg));

    let mut ct = [0u8; CT];
    encode_poly::<N>(&u, &mut ct[..2 * N]);
    encode_poly::<N>(&v, &mut ct[2 * N..]);
    ct
}

/// Deterministic CPAPKE decryption.
fn pke_decrypt<const N: usize>(ctx: &NttContext<N>, s: &Poly<N>, ct: &[u8]) -> [u8; SEED_LEN] {
    let u = decode_poly::<N>(&ct[..2 * N]);
    let v = decode_poly::<N>(&ct[2 * N..]);
    let w = v.sub(&ctx.mul(&u, s));
    poly_to_msg::<N>(&w)
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
///
/// `N` is the ring dimension; `PK`, `SK` and `CT` are the derived byte lengths.
/// Construct via the [`ReKem`] / [`ReKem1024`] aliases so the relation is
/// always consistent.
pub struct KemGeneric<const N: usize, const PK: usize, const SK: usize, const CT: usize> {
    ctx: NttContext<N>,
}

/// RE-KEM at `n = 512` (NewHope-512 parameter regime). The default set.
pub type ReKem = KemGeneric<{ crate::params::NEWHOPE_512.n }, PK_LEN, SK_LEN, CT_LEN>;

/// RE-KEM at `n = 1024`.
///
/// Offered on the basis of the noise-model bound in
/// `docs/error-probability.md` and byte-level cross-validation against the
/// Python reference at `n = 1024` — **not** on the NewHope-1024 analysis,
/// which assumes a different message encoding.
pub type ReKem1024 = KemGeneric<{ crate::params::LEVEL5_1024.n }, PK_LEN_1024, SK_LEN_1024, CT_LEN_1024>;

impl<const N: usize, const PK: usize, const SK: usize, const CT: usize> Default
    for KemGeneric<N, PK, SK, CT>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize, const PK: usize, const SK: usize, const CT: usize>
    KemGeneric<N, PK, SK, CT>
{
    pub fn new() -> Self {
        KemGeneric {
            ctx: NttContext::<N>::new(),
        }
    }

    /// The ring dimension this instance works in.
    pub const fn dimension(&self) -> usize {
        N
    }

    /// Checks `PK = 32 + 2N`, `SK = 2N + PK + 64`, `CT = 4N`.
    ///
    /// A mismatch means someone instantiated `KemGeneric` by hand with
    /// inconsistent lengths. The slices below are then wrong, so this is worth
    /// asserting rather than discovering through a panic on a secret path.
    pub fn sizes_are_consistent(&self) -> bool {
        PK == SEED_LEN + 2 * N
            && SK == 2 * N + PK + 32 + SEED_LEN
            && CT == 4 * N
    }

    /// Deterministic key generation from explicit seeds (for test vectors).
    pub fn keygen_derand(
        &self,
        seed_a: &[u8; SEED_LEN],
        noise_seed: &[u8; SEED_LEN],
        z: &[u8; SEED_LEN],
    ) -> ([u8; PK], [u8; SK]) {
        debug_assert!(self.sizes_are_consistent());
        let a = expand_a::<N>(seed_a);
        let s = cbd_sample::<N>(noise_seed, 0);
        let e = cbd_sample::<N>(noise_seed, 1);
        let b = self.ctx.mul(&a, &s).add(&e);

        let mut pk = [0u8; PK];
        pk[..SEED_LEN].copy_from_slice(seed_a);
        encode_poly::<N>(&b, &mut pk[SEED_LEN..]);

        let hp = h_pk(&pk);

        let mut sk = [0u8; SK];
        encode_poly::<N>(&s, &mut sk[..2 * N]);
        sk[2 * N..2 * N + PK].copy_from_slice(&pk);
        sk[2 * N + PK..2 * N + PK + 32].copy_from_slice(&hp);
        sk[2 * N + PK + 32..].copy_from_slice(z);

        (pk, sk)
    }

    /// Key generation with fresh randomness.
    #[cfg(feature = "rng")]
    pub fn keygen(&self) -> ([u8; PK], [u8; SK]) {
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
    pub fn encaps_derand(&self, pk: &[u8; PK], m: &[u8; SEED_LEN]) -> ([u8; CT], [u8; SS_LEN]) {
        debug_assert!(self.sizes_are_consistent());
        let hp = h_pk(pk);
        // k_bar and the encapsulation coins are secret; wipe them on scope exit.
        let (k_bar, coins) = g_fn(m, &hp);
        let k_bar = Zeroizing::new(k_bar);
        let coins = Zeroizing::new(coins);
        let ct = pke_encrypt::<N, CT>(&self.ctx, pk, m, &coins[..]);
        let hc = h_ct(&ct);
        let ss = kdf(&k_bar, &hc);
        (ct, ss)
    }

    /// Encapsulation with fresh randomness.
    #[cfg(feature = "rng")]
    pub fn encaps(&self, pk: &[u8; PK]) -> ([u8; CT], [u8; SS_LEN]) {
        let mut m = Zeroizing::new([0u8; SEED_LEN]);
        getrandom::getrandom(&mut *m).expect("OS randomness unavailable");
        self.encaps_derand(pk, &m)
    }

    /// Decapsulation with implicit rejection (never fails; returns a
    /// pseudorandom secret on invalid ciphertexts).
    pub fn decaps(&self, sk: &[u8; SK], ct: &[u8; CT]) -> [u8; SS_LEN] {
        debug_assert!(self.sizes_are_consistent());
        let s = decode_poly::<N>(&sk[..2 * N]);

        let mut pk = [0u8; PK];
        pk.copy_from_slice(&sk[2 * N..2 * N + PK]);

        let mut hp = [0u8; 32];
        hp.copy_from_slice(&sk[2 * N + PK..2 * N + PK + 32]);

        let mut z = [0u8; SEED_LEN];
        z.copy_from_slice(&sk[2 * N + PK + 32..]);

        // 1. candidate plaintext (secret — wiped on exit)
        let m_prime = Zeroizing::new(pke_decrypt::<N>(&self.ctx, &s, ct));

        // 2. re-derive the encapsulation coins
        let (k_bar_prime, coins_prime) = g_fn(&m_prime, &hp);
        let k_bar_prime = Zeroizing::new(k_bar_prime);
        let coins_prime = Zeroizing::new(coins_prime);

        // 3. re-encrypt
        let ct_prime = pke_encrypt::<N, CT>(&self.ctx, &pk, &m_prime, &coins_prime[..]);

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
    fn size_invariants_hold() {
        // The relation the const parameters must satisfy. Cheap, and it turns
        // a whole class of silent slicing bugs into a test failure.
        assert!(ReKem::new().sizes_are_consistent());
        assert!(ReKem1024::new().sizes_are_consistent());
        assert_eq!(PK_LEN, 1056);
        assert_eq!(SK_LEN, 2144);
        assert_eq!(CT_LEN, 2048);
        assert_eq!(PK_LEN_1024, 2080);
        assert_eq!(SK_LEN_1024, 4192);
        assert_eq!(CT_LEN_1024, 4096);
    }

    fn roundtrip<const N: usize, const PK: usize, const SK: usize, const CT: usize>(
        kem: &KemGeneric<N, PK, SK, CT>,
        tag: &str,
    ) {
        let (pk, sk) = kem.keygen_derand(&[1u8; 32], &[2u8; 32], &[3u8; 32]);
        let (ct, ss_tx) = kem.encaps_derand(&pk, &[4u8; 32]);
        let ss_rx = kem.decaps(&sk, &ct);

        assert_eq!(ss_tx, ss_rx, "{tag}: shared secrets must match");
        assert_eq!(pk.len(), PK);
        assert_eq!(sk.len(), SK);
        assert_eq!(ct.len(), CT);

        // tampering must never yield the real secret
        let mut bad = ct;
        bad[17] ^= 0x01;
        assert_ne!(kem.decaps(&sk, &bad), ss_tx, "{tag}: IND-CCA2 must reject");

        // wrong secret key must not yield the real secret either
        let (_pk2, sk2) = kem.keygen_derand(&[9u8; 32], &[8u8; 32], &[7u8; 32]);
        assert_ne!(kem.decaps(&sk2, &ct), ss_tx, "{tag}: wrong key must not match");
    }

    #[test]
    fn keygen_encaps_decaps_roundtrip_n512() {
        roundtrip(&ReKem::new(), "n=512");
    }

    /// The second parameter set end to end. Correctness here is *not* inherited
    /// from n=512: different dimension, different noise accumulation.
    #[test]
    fn keygen_encaps_decaps_roundtrip_n1024() {
        roundtrip(&ReKem1024::new(), "n=1024");
    }

    #[test]
    fn deterministic_reproducibility() {
        for tag in ["512", "1024"] {
            if tag == "512" {
                let kem = ReKem::new();
                let (pk1, sk1) = kem.keygen_derand(&[20u8; 32], &[21u8; 32], &[22u8; 32]);
                let (pk2, sk2) = kem.keygen_derand(&[20u8; 32], &[21u8; 32], &[22u8; 32]);
                assert_eq!(pk1, pk2);
                assert_eq!(sk1, sk2);
                let (ct1, ss1) = kem.encaps_derand(&pk1, &[23u8; 32]);
                let (ct2, ss2) = kem.encaps_derand(&pk2, &[23u8; 32]);
                assert_eq!(ct1, ct2);
                assert_eq!(ss1, ss2);
            } else {
                let kem = ReKem1024::new();
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
    }

    #[test]
    fn tampered_ciphertext_gives_different_secret() {
        let kem = ReKem::new();
        let (pk, sk) = kem.keygen_derand(&[1u8; 32], &[2u8; 32], &[3u8; 32]);
        let (ct, ss) = kem.encaps_derand(&pk, &[4u8; 32]);
        let mut bad = ct;
        bad[100] ^= 0x01;
        assert_ne!(kem.decaps(&sk, &bad), ss);
    }

    #[test]
    fn wrong_secret_key_gives_different_secret() {
        let kem = ReKem::new();
        let (pk1, _sk1) = kem.keygen_derand(&[1u8; 32], &[2u8; 32], &[3u8; 32]);
        let (_pk2, sk2) = kem.keygen_derand(&[5u8; 32], &[6u8; 32], &[7u8; 32]);
        let (ct, ss) = kem.encaps_derand(&pk1, &[4u8; 32]);
        assert_ne!(kem.decaps(&sk2, &ct), ss);
    }

    #[test]
    fn lengths_match_reference() {
        let kem = ReKem::new();
        let (pk, sk) = kem.keygen_derand(&[1u8; 32], &[2u8; 32], &[3u8; 32]);
        let (ct, ss) = kem.encaps_derand(&pk, &[4u8; 32]);
        assert_eq!(pk.len(), 1056);
        assert_eq!(sk.len(), 2144);
        assert_eq!(ct.len(), 2048);
        assert_eq!(ss.len(), 32);
    }

    /// Regression guard for the branchless recentring in `poly_to_msg`.
    ///
    /// An earlier revision used `v + (q & mask)` instead of `v - (q & mask)`,
    /// which added q instead of subtracting it for every coefficient above
    /// q/2 — silently wrong on 3072 of 12289 possible values, caught only by
    /// the Python cross-validation. This test checks *every* value.
    #[test]
    fn branchless_recentring_matches_naive_for_all_values() {
        let q = Q as i32;
        let half_q = q / 2;
        let quarter_q = q / 4;

        for v in 0..q {
            let mask = (half_q - v) >> 31;
            let centred = v - (q & mask);
            let sign = centred >> 31;
            let abs = (centred + sign) ^ sign;
            let got = ((quarter_q - abs) >> 31) & 1;

            let n_centred = if v > half_q { v - q } else { v };
            let n_abs = if n_centred < 0 { -n_centred } else { n_centred };
            let want = (n_abs > quarter_q) as i32;

            assert_eq!(got, want, "recentring mismatch at v = {v}");
        }
    }

    /// Regression guard for the branchless message embedding: every bit
    /// pattern must land on the same coefficients as the naive form — and at
    /// n=1024 the padding coefficients must stay zero.
    #[test]
    fn branchless_msg_embedding_matches_naive() {
        let half = (Q / 2) as u16;
        for byte in [0u8, 1, 0x55, 0xAA, 0xFF, 0x7F, 0x80] {
            let msg = [byte; SEED_LEN];

            let p = msg_to_poly::<512>(&msg);
            for i in 0..(SEED_LEN * 8) {
                let want = if msg_bit(&msg, i) == 1 { half } else { 0 };
                assert_eq!(p.coeffs[i].to_plain(), want, "n=512 byte {byte:#04x} bit {i}");
            }
            for i in (SEED_LEN * 8)..512 {
                assert_eq!(p.coeffs[i].to_plain(), 0, "n=512 padding at {i}");
            }

            let q = msg_to_poly::<1024>(&msg);
            for i in 0..(SEED_LEN * 8) {
                let want = if msg_bit(&msg, i) == 1 { half } else { 0 };
                assert_eq!(q.coeffs[i].to_plain(), want, "n=1024 byte {byte:#04x} bit {i}");
            }
            for i in (SEED_LEN * 8)..1024 {
                assert_eq!(q.coeffs[i].to_plain(), 0, "n=1024 padding at {i}");
            }
        }
    }
}
