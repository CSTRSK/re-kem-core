//! Sampling: Centered Binomial Distribution and uniform expansion of a(x).
//!
//! Ported 1:1 from the Python reference (`rekem.py::_cbd_sample`, `_expand_a`).
//! Bit ordering matters: NumPy's `unpackbits` emits the **most significant bit
//! first** within each byte, and the Python code reshapes the stream into
//! `n` rows of `2*eta` bits. Any deviation here changes every derived key.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake256, Shake256Reader};

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

use crate::field::FieldElement;
use crate::ntt::{Poly, N};

/// CBD noise parameter (NewHope-512 regime).
pub const ETA: usize = 8;

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
pub fn cbd_sample(seed: &[u8], nonce: u8) -> Poly {
    let bits_per_coeff = 2 * ETA;
    let total_bits = bits_per_coeff * N;
    let total_bytes = (total_bits + 7) / 8;

    let mut reader = shake256_xof(seed, nonce);
    let mut raw = vec![0u8; total_bytes];
    reader.read(&mut raw);

    let mut out = Poly::zero();
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
        // coefficient in [-eta, eta]; map into Z_q
        let v = (a - b).rem_euclid(crate::field::Q as i32) as u16;
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
/// must be consumed identically.
pub fn expand_a(seed: &[u8]) -> Poly {
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

    let mut out = Poly::zero();
    for i in 0..N {
        out.coeffs[i] = FieldElement::from_plain(coeffs[i]);
    }
    out
}

/// Packs a polynomial into `2*N` bytes, little-endian per coefficient.
pub fn encode_poly(p: &Poly) -> [u8; 2 * N] {
    let mut buf = [0u8; 2 * N];
    for i in 0..N {
        let v = p.coeffs[i].to_plain();
        buf[2 * i] = (v & 0xFF) as u8;
        buf[2 * i + 1] = (v >> 8) as u8;
    }
    buf
}

/// Inverse of [`encode_poly`].
pub fn decode_poly(data: &[u8]) -> Poly {
    let mut out = Poly::zero();
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

    #[test]
    fn cbd_values_within_eta_range() {
        let seed = [7u8; 32];
        let p = cbd_sample(&seed, 0);
        for i in 0..N {
            let v = p.coeffs[i].to_plain() as i32;
            // stored mod q; recentre to [-q/2, q/2]
            let centred = if v > (Q as i32) / 2 { v - Q as i32 } else { v };
            assert!(
                centred >= -(ETA as i32) && centred <= ETA as i32,
                "coefficient {i} = {centred} outside [-{ETA}, {ETA}]"
            );
        }
    }

    #[test]
    fn cbd_is_deterministic() {
        let seed = [42u8; 32];
        let a = cbd_sample(&seed, 1);
        let b = cbd_sample(&seed, 1);
        assert_eq!(a, b);
        let c = cbd_sample(&seed, 2);
        assert_ne!(a, c, "different nonce must give different noise");
    }

    #[test]
    fn expand_a_rejection_sampling_yields_uniform_range() {
        let seed = [3u8; 32];
        let a = expand_a(&seed);
        for i in 0..N {
            assert!((a.coeffs[i].to_plain() as usize) < Q as usize);
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let seed = [9u8; 32];
        let p = expand_a(&seed);
        let enc = encode_poly(&p);
        let dec = decode_poly(&enc);
        assert_eq!(p, dec);
    }
}
