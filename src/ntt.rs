//! Negacyclic Number-Theoretic Transform over Z_q, q = 12289, n = 512.
//!
//! Ported 1:1 from the Python reference (`rekem.py::_ntt`, `_poly_mul_ntt`).
//! The mathematical result is unique, so the implementation strategy need not
//! match — only the output must.
//!
//! Ring: Z_q[X] / (X^n + 1). Multiplication is done by
//!   1. twisting each coefficient with psi^i
//!   2. forward NTT with omega = psi^2
//!   3. pointwise product
//!   4. inverse NTT with omega^-1, scaled by n^-1
//!   5. untwisting with psi^-i

use crate::field::{FieldElement, Q};
use zeroize::Zeroize;

/// Number of coefficients.
pub const N: usize = 512;

/// A polynomial with N coefficients in Montgomery form.
///
/// Deliberately **not** `Copy`: polynomials hold secret material (s, e, r, the
/// decrypted message candidate). Implementing `Drop` + `Zeroize` means every
/// such buffer is wiped when it goes out of scope, so secrets do not linger in
/// freed memory. This costs a `Clone` at the few places that need a duplicate —
/// a deliberate trade for a crypto type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Poly {
    pub coeffs: [FieldElement; N],
}

impl zeroize::Zeroize for Poly {
    #[inline]
    fn zeroize(&mut self) {
        self.coeffs.iter_mut().for_each(|c| c.zeroize());
    }
}

impl Drop for Poly {
    #[inline]
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Poly {
    /// The all-zero polynomial.
    pub fn zero() -> Poly {
        Poly {
            coeffs: [FieldElement::zero(); N],
        }
    }

    pub fn add(&self, other: &Poly) -> Poly {
        let mut out = Poly::zero();
        for i in 0..N {
            out.coeffs[i] = self.coeffs[i].add(other.coeffs[i]);
        }
        out
    }

    pub fn sub(&self, other: &Poly) -> Poly {
        let mut out = Poly::zero();
        for i in 0..N {
            out.coeffs[i] = self.coeffs[i].sub(other.coeffs[i]);
        }
        out
    }

    /// Multiply by a scalar field element.
    pub fn scale(&self, k: FieldElement) -> Poly {
        let mut out = Poly::zero();
        for i in 0..N {
            out.coeffs[i] = self.coeffs[i].mul(k);
        }
        out
    }
}

/// Precomputed twiddle factors for the negacyclic NTT.
#[derive(Clone)]
pub struct NttContext {
    /// psi^i mod q — used for twisting.
    psi_powers: [u16; N],
    /// psi^-i mod q — used for untwisting.
    psi_inv_powers: [u16; N],
    /// psi, a primitive 2n-th root of unity (psi^n = -1).
    psi: u16,
    /// omega = psi^2, a primitive n-th root of unity.
    omega: u16,
    omega_inv: u16,
    n_inv: u16,
}

/// Modular exponentiation (plain u64 math; not secret-dependent input here).
fn pow_mod(base: u32, exp: u32, m: u32) -> u32 {
    let mut result: u64 = 1;
    let mut b = (base as u64) % (m as u64);
    let mut e = exp;
    let mm = m as u64;
    while e > 0 {
        if e & 1 == 1 {
            result = (result * b) % mm;
        }
        b = (b * b) % mm;
        e >>= 1;
    }
    result as u32
}

/// Finds a primitive 2n-th root of unity psi with psi^n = -1 (mod q).
fn find_primitive_root_2n(q: u32, n: u32) -> u16 {
    for g in 2u32..q {
        // g must be a quadratic non-residue
        if pow_mod(g, (q - 1) / 2, q) == q - 1 {
            let cand = pow_mod(g, (q - 1) / (2 * n), q);
            if pow_mod(cand, n, q) == q - 1 {
                return cand as u16;
            }
        }
    }
    panic!("no 2n-th root of unity found");
}

impl NttContext {
    /// Builds the context (deterministic, no secret input).
    pub fn new() -> NttContext {
        let psi = find_primitive_root_2n(Q, N as u32);
        let psi_inv = pow_mod(psi as u32, Q - 2, Q) as u16; // Fermat inverse
        let omega = pow_mod(psi as u32, 2, Q) as u16;
        let omega_inv = pow_mod(omega as u32, Q - 2, Q) as u16;
        let n_inv = pow_mod(N as u32, Q - 2, Q) as u16;

        let mut psi_powers = [0u16; N];
        let mut psi_inv_powers = [0u16; N];
        let mut cur: u64 = 1;
        for i in 0..N {
            psi_powers[i] = cur as u16;
            cur = (cur * psi as u64) % Q as u64;
        }
        cur = 1;
        for i in 0..N {
            psi_inv_powers[i] = cur as u16;
            cur = (cur * psi_inv as u64) % Q as u64;
        }

        NttContext {
            psi_powers,
            psi_inv_powers,
            psi,
            omega,
            omega_inv,
            n_inv,
        }
    }

    pub fn psi(&self) -> u16 {
        self.psi
    }

    /// In-place radix-2 Cooley-Tukey NTT with bit-reversal permutation.
    fn ntt_plain(&self, a: &mut [u16; N], root: u16) {
        // bit-reversal permutation
        let mut j = 0usize;
        for i in 1..N {
            let mut bit = N >> 1;
            while j & bit != 0 {
                j ^= bit;
                bit >>= 1;
            }
            j ^= bit;
            if i < j {
                a.swap(i, j);
            }
        }

        let mut length = 2usize;
        while length <= N {
            let wlen = pow_mod(root as u32, (N / length) as u32, Q) as u64;
            let half = length / 2;
            let mut i = 0usize;
            while i < N {
                let mut w: u64 = 1;
                for k in 0..half {
                    let u = a[i + k] as u64;
                    let v = ((a[i + k + half] as u64) * w) % Q as u64;
                    let sum = u + v;
                    let diff = u + Q as u64 - v;
                    a[i + k] = (sum % Q as u64) as u16;
                    a[i + k + half] = (diff % Q as u64) as u16;
                    w = (w * wlen) % Q as u64;
                }
                i += length;
            }
            length <<= 1;
        }
    }

    /// Negacyclic polynomial multiplication mod (X^n + 1).
    pub fn mul(&self, a: &Poly, b: &Poly) -> Poly {
        let mut a_tw = [0u16; N];
        let mut b_tw = [0u16; N];

        // 1. Twist
        for i in 0..N {
            a_tw[i] = ((a.coeffs[i].to_plain() as u64 * self.psi_powers[i] as u64) % Q as u64) as u16;
            b_tw[i] = ((b.coeffs[i].to_plain() as u64 * self.psi_powers[i] as u64) % Q as u64) as u16;
        }

        // 2. Forward NTT
        self.ntt_plain(&mut a_tw, self.omega);
        self.ntt_plain(&mut b_tw, self.omega);

        // 3. Pointwise product
        let mut c_hat = [0u16; N];
        for i in 0..N {
            c_hat[i] = ((a_tw[i] as u64 * b_tw[i] as u64) % Q as u64) as u16;
        }

        // 4. Inverse NTT + scale by n^-1
        self.ntt_plain(&mut c_hat, self.omega_inv);
        for i in 0..N {
            c_hat[i] = ((c_hat[i] as u64 * self.n_inv as u64) % Q as u64) as u16;
        }

        // 5. Untwist
        let mut out = Poly::zero();
        for i in 0..N {
            let v = ((c_hat[i] as u64 * self.psi_inv_powers[i] as u64) % Q as u64) as u16;
            out.coeffs[i] = FieldElement::from_plain(v);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Naive schoolbook negacyclic multiplication for cross-checking.
    fn naive_mul(a: &[u16; N], b: &[u16; N]) -> [u16; N] {
        let mut out = [0u32; N];
        for i in 0..N {
            for j in 0..N {
                let prod = (a[i] as u32) * (b[j] as u32);
                let k = i + j;
                if k < N {
                    out[k] = (out[k] + prod) % Q;
                } else {
                    // X^(i+j) = X^(i+j-n) * X^n = -X^(i+j-n)  (mod X^n + 1)
                    let idx = k - N;
                    out[idx] = (out[idx] + Q - (prod % Q)) % Q;
                }
            }
        }
        let mut res = [0u16; N];
        for i in 0..N {
            res[i] = out[i] as u16;
        }
        res
    }

    #[test]
    fn psi_is_primitive_2n_root() {
        let ctx = NttContext::new();
        let psi = ctx.psi() as u32;
        // psi^n == -1 mod q  <=>  psi^(2n) == 1
        assert_eq!(pow_mod(psi, 2 * N as u32, Q), 1);
        assert_eq!(pow_mod(psi, N as u32, Q), Q - 1);
    }

    #[test]
    fn ntt_multiplication_matches_naive() {
        let ctx = NttContext::new();
        let mut a_raw = [0u16; N];
        let mut b_raw = [0u16; N];
        // deterministic spread of values
        for i in 0..N {
            a_raw[i] = ((i * 37 + 11) % Q as usize) as u16;
            b_raw[i] = ((i * 91 + 7) % Q as usize) as u16;
        }
        let mut a = Poly::zero();
        let mut b = Poly::zero();
        for i in 0..N {
            a.coeffs[i] = FieldElement::from_plain(a_raw[i]);
            b.coeffs[i] = FieldElement::from_plain(b_raw[i]);
        }

        let got = ctx.mul(&a, &b);
        let expected = naive_mul(&a_raw, &b_raw);
        for i in 0..N {
            assert_eq!(
                got.coeffs[i].to_plain(),
                expected[i],
                "mismatch at coefficient {i}"
            );
        }
    }

    #[test]
    fn multiplication_with_negacyclic_wrap() {
        // X^(n-1) * X = X^n = -1  (mod X^n + 1)
        let ctx = NttContext::new();
        let mut a = Poly::zero();
        let mut b = Poly::zero();
        a.coeffs[N - 1] = FieldElement::from_plain(1);
        b.coeffs[1] = FieldElement::from_plain(1);

        let c = ctx.mul(&a, &b);
        assert_eq!(c.coeffs[0].to_plain(), Q as u16 - 1, "X^n must wrap to -1");
        for i in 1..N {
            assert_eq!(c.coeffs[i].to_plain(), 0);
        }
    }
}
