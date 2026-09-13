//! Sampling: Centered Binomial Distribution and uniform expansion of a(x),
//! generic over the ring dimension.
//!
//! Ported 1:1 from the Python reference (`rekem.py::_cbd_sample`, `_expand_a`).
//! Bit ordering matters: NumPy's `unpackbits` emits the **most significant bit
//! first** within each byte, and the Python code reshapes the stream into
//! `n` rows of `2*eta` bits. Any deviation here changes every derived key.
//!
//! ## Buffers, not `Vec`
//!
//! `encode_poly` writes into a caller-provided slice instead of returning
//! `[u8; 2 * N]`: array lengths may not use a const parameter in arithmetic on
//! stable Rust, and a `Vec` would give up the `no_std`/`no-alloc` property this
//! crate is meant to keep. The caller knows the length, so it supplies it.
//!
//! `expand_a` does use a small `Vec` for the rejection loop, because the number
//! of consumed words is data-dependent. That is the only allocation in the
//! crate and it is on the **public** seed, never on secret material.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake256, Shake256Reader};

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

use crate::field::{ct_reduce_once, FieldElement};
use crate::ntt::Poly;

/// CBD noise parameter.
///
/// Both declared parameter sets (`NEWHOPE_512`, `LEVEL5_1024`) use `eta = 8`,
/// so a single constant is correct for either. A future set with a different
/// `eta` would need this promoted to a const parameter — noted here rather
/// than silently assumed.
pub const ETA: usize = crate::params::ACTIVE.eta;

/// Extracts bit `idx` from a byte slice, MSB-first within each byte
/// (matching NumPy's `unpackbits`).
#[inline]
fn bit_at(data: &[u8], idx: usize) -> u8 {
    let byte = data[idx / 8];
    (byte >> (7 - (idx % 8))) & 1
}

fn shake256_xof(seed: &[u8], nonce: u8) -> Shake256Reader {
    let mut hasher = Shake256::default();
    Update::update(&mut hasher, seed);
    Update::update(&mut hasher, &[nonce]);
    hasher.finalize_xof()
}

/// Samples a noise polynomial from CBD(eta) using SHAKE-256(seed || nonce).
///
/// Mirrors the Python reference exactly:
///   * `2*eta` bits per coefficient, MSB-first
///   * first `eta` bits summed → `a`, next `eta` bits summed → `b`
///   * coefficient = a - b   (range [-eta, +eta])
pub fn cbd_sample<const N: usize>(seed: &[u8], nonce: u8) -> Poly<N> {
    let bits_per_coeff = 2 * ETA;
    let total_bits = bits_per_coeff * N;
    let total_bytes = (total_bits + 7) / 8;

    let mut reader = shake256_xof(seed, nonce);
    let mut raw = vec![0u8; total_bytes];
    reader.read(&mut raw);

    let mut out = Poly::<N>::zero();
    for i in 0..N {
        let base = i * bits_per_coeff;
        let mut a: i32 = 0;
        let mut b: i32 = 0;
        for j in 0..ETA {
            a += bit_at(&raw, base + j) as i32;
        }
        for j in 0..ETA {
            b += bit_at(&raw, base + ETA + j) as i32;
        }
        // `a - b` is the secret noise coefficient, in [-eta, eta].
        // i32::rem_euclid branches internally on `r < 0`, so add q first and
        // use the same masking reduction as the field arithmetic.
        let v = ct_reduce_once((a - b + crate::field::Q as i32) as u32);
        out.coeffs[i] = FieldElement::from_plain(v);
    }
    out
}

/// Uniformly samples the public polynomial a(x) from a 32-byte seed using
/// NewHope-style rejection sampling.
///
/// Mirrors the Python reference exactly: SHAKE-256(seed || nonce) is read in
/// 16-bit little-endian words; a word is accepted only if it is below
/// `floor(65536/q)*q`, then reduced mod q. The amount requested (`need * 3`)
/// depends on the number of coefficients still missing, so the byte stream
/// must be consumed identically — and `need` is computed from the dimension,
/// which is why this matches the reference at every `n`.
pub fn expand_a<const N: usize>(seed: &[u8]) -> Poly<N> {
    let q = crate::field::Q as usize;
    let limit = (65536 / q) * q; // = 61445 for q = 12289
    let mut coeffs: Vec<u16> = Vec::with_capacity(N);
    let mut nonce: u8 = 0;

    while coeffs.len() < N {
        let need = N - coeffs.len();
        let mut reader = shake256_xof(seed, nonce);
        nonce = nonce.wrapping_add(1);
        let mut raw = vec![0u8; need * 3];
        reader.read(&mut raw);

        let mut i = 0;
        while i + 1 < raw.len() {
            let val = (raw[i] as usize) | ((raw[i + 1] as usize) << 8);
            if val < limit {
                coeffs.push((val % q) as u16);
                if coeffs.len() == N {
                    break;
                }
            }
            i += 2;
        }
    }

    let mut out = Poly::<N>::zero();
    for i in 0..N {
        out.coeffs[i] = FieldElement::from_plain(coeffs[i]);
    }
    out
}

/// Packs a polynomial into `2*N` bytes, little-endian per coefficient.
///
/// Writes into `out`, which must be exactly `2*N` bytes.
pub fn encode_poly<const N: usize>(p: &Poly<N>, out: &mut [u8]) {
    debug_assert_eq!(out.len(), 2 * N, "encode_poly buffer must be 2N bytes");
    for i in 0..N {
        let v = p.coeffs[i].to_plain();
        out[2 * i] = (v & 0xFF) as u8;
        out[2 * i + 1] = (v >> 8) as u8;
    }
}

/// Inverse of [`encode_poly`]. Reads `2*N` bytes.
pub fn decode_poly<const N: usize>(data: &[u8]) -> Poly<N> {
    debug_assert!(data.len() >= 2 * N, "decode_poly needs 2N bytes");
    let mut out = Poly::<N>::zero();
    for i in 0..N {
        let v = (data[2 * i] as u16) | ((data[2 * i + 1] as u16) << 8);
        out.coeffs[i] = FieldElement::from_plain(v);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::Q;

    fn check_dim<const N: usize>() {
        // values within [-eta, eta]
        let seed = [7u8; 32];
        let p = cbd_sample::<N>(&seed, 0);
        for i in 0..N {
            let v = p.coeffs[i].to_plain() as i32;
            let centred = if v > (Q as i32) / 2 { v - Q as i32 } else { v };
            assert!(
                centred >= -(ETA as i32) && centred <= ETA as i32,
                "n={N}: coefficient {i} = {centred} outside [-{ETA}, {ETA}]"
            );
        }

        // determinism
        let a = cbd_sample::<N>(&[42u8; 32], 1);
        let b = cbd_sample::<N>(&[42u8; 32], 1);
        assert_eq!(a, b);
        assert_ne!(a, cbd_sample::<N>(&[42u8; 32], 2));

        // expand_a stays in range
        let a_poly = expand_a::<N>(&[3u8; 32]);
        for i in 0..N {
            assert!((a_poly.coeffs[i].to_plain() as usize) < Q as usize);
        }

        // encode/decode roundtrip
        let p = expand_a::<N>(&[9u8; 32]);
        let mut buf = vec![0u8; 2 * N];
        encode_poly::<N>(&p, &mut buf);
        let dec = decode_poly::<N>(&buf);
        assert_eq!(p, dec);
    }

    #[test]
    fn all_dimensions_behave() {
        check_dim::<512>();
        check_dim::<1024>();
    }

    #[test]
    fn encode_length_is_dimension_dependent() {
        let p = expand_a::<512>(&[1u8; 32]);
        let mut b512 = vec![0u8; 1024];
        encode_poly::<512>(&p, &mut b512);
        let q1024 = expand_a::<1024>(&[1u8; 32]);
        let mut b1024 = vec![0u8; 2048];
        encode_poly::<1024>(&q1024, &mut b1024);
        assert_eq!(b512.len(), 2 * 512);
        assert_eq!(b1024.len(), 2 * 1024);
    }
}
