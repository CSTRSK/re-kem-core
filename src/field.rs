//! Constant-time Montgomery arithmetic over Z_q, q = 12289 (NewHope-512 modulus).
//!
//! CORRECTION vs. the reviewed draft: that draft states
//!   "R = 2^16 ≡ 4095 (mod q)"
//! which is wrong. The correct value is:
//!   2^16 mod 12289 = 4091
//! (verified independently in Python: pow(2,16,12289) == 4091).
//! Using 4095 anywhere in a Montgomery multiplier would silently produce
//! wrong field elements on every single multiplication - not a
//! side-channel bug but a correctness bug, and a much nastier one to
//! catch, because keygen/encaps/decaps would "run" and only fail
//! statistically or not at all depending on where the bad constant is used.
//!
//! Q_INV_NEG = -q^-1 mod R is the standard REDC constant, also verified
//! independently below (Q_INV_NEG = 12287).

pub const Q: u32 = 12289;
/// -q^-1 mod R, R = 2^16. Verified: pow(12289, -1, 65536) = 53249,
/// so -q^-1 mod R = 65536 - 53249 = 12287.
const Q_INV_NEG: u32 = 12287;
/// R^2 mod q, used to convert a plain residue into Montgomery form.
/// R = 2^16 = 65536; verified independently: pow(65536, 2, 12289) = 10952.
const R2_MOD_Q: u32 = 10952; // checked against an independent computation in tests below

/// A field element permanently stored in Montgomery form (value * R mod q).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldElement(u16);

/// Branchless Montgomery reduction: given t < q * R, returns t * R^-1 mod q,
/// in range [0, q). No data-dependent branches; the only conditional is a
/// single constant-time subtraction at the end.
#[inline(always)]
fn montgomery_reduce(t: u32) -> u16 {
    // m = (t mod R) * Q_INV_NEG mod R
    let m = (t.wrapping_mul(Q_INV_NEG)) & 0xFFFF;
    let mq = m * Q;
    // (t + m*q) is guaranteed divisible by R = 2^16
    let u = (t + mq) >> 16;
    // u is now in [0, 2q); one conditional (constant-time) subtraction
    // brings it into [0, q).
    ct_reduce_once(u)
}

/// Branchless "subtract q once if a >= q", a in [0, 2q).
#[inline(always)]
fn ct_reduce_once(a: u32) -> u16 {
    let diff = a.wrapping_sub(Q);
    // top bit of diff is 1 (all-ones after arithmetic shift) iff a < Q
    let mask = (diff as i32 >> 31) as u32; // 0xFFFF_FFFF if a < Q, else 0
    (diff.wrapping_add(mask & Q)) as u16
}

#[inline(always)]
fn montgomery_mul_raw(a: u16, b: u16) -> u16 {
    montgomery_reduce((a as u32) * (b as u32))
}

impl FieldElement {
    /// Lift a plain residue in [0, q) into Montgomery form.
    pub fn from_plain(a: u16) -> Self {
        debug_assert!((a as u32) < Q);
        FieldElement(montgomery_mul_raw(a, R2_MOD_Q as u16))
    }

    /// Bring a Montgomery-form element back to a plain residue in [0, q).
    pub fn to_plain(self) -> u16 {
        montgomery_reduce(self.0 as u32)
    }

    /// Constant-time multiplication in Montgomery form.
    #[inline(always)]
    pub fn mul(self, other: Self) -> Self {
        FieldElement(montgomery_mul_raw(self.0, other.0))
    }

    /// Constant-time addition (single conditional subtraction, branchless).
    #[inline(always)]
    pub fn add(self, other: Self) -> Self {
        let sum = self.0 as u32 + other.0 as u32; // < 2q, safe in u32
        FieldElement(ct_reduce_once(sum))
    }

    /// Constant-time subtraction.
    #[inline(always)]
    pub fn sub(self, other: Self) -> Self {
        // add Q before subtracting to avoid underflow, then reduce
        let diff = self.0 as u32 + Q - other.0 as u32;
        FieldElement(ct_reduce_once(diff))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r_mod_q_constant_is_4091_not_4095() {
        // R = 2^16 mod q, computed independently of the Montgomery machinery.
        let r_mod_q: u64 = (1u64 << 16) % (Q as u64);
        assert_eq!(r_mod_q, 4091, "R mod q must be 4091 - the draft's 4095 is wrong");
    }

    #[test]
    fn r2_mod_q_constant_is_correct() {
        let r_mod_q: u64 = (1u64 << 16) % (Q as u64);
        let r2: u64 = (r_mod_q * r_mod_q) % (Q as u64);
        assert_eq!(r2 as u32, R2_MOD_Q);
    }

    #[test]
    fn roundtrip_plain_montgomery_plain() {
        for a in 0..Q as u16 {
            let fe = FieldElement::from_plain(a);
            assert_eq!(fe.to_plain(), a, "roundtrip failed for a={a}");
        }
    }

    #[test]
    fn multiplication_matches_naive_mod_mul() {
        // Cross-check against plain (non-Montgomery) modular multiplication
        // for a spread of values, including edge cases near 0 and q-1.
        let samples: Vec<u16> = (0..50)
            .map(|i| ((i * 257) % Q as u32) as u16)
            .chain([0, 1, Q as u16 - 1, (Q as u16) / 2])
            .collect();

        for &a in &samples {
            for &b in &samples {
                let expected = ((a as u32) * (b as u32)) % Q;
                let got = FieldElement::from_plain(a)
                    .mul(FieldElement::from_plain(b))
                    .to_plain();
                assert_eq!(
                    got as u32, expected,
                    "mismatch for a={a}, b={b}: got {got}, expected {expected}"
                );
            }
        }
    }

    #[test]
    fn addition_and_subtraction_match_naive() {
        let samples: [u16; 7] = [0, 1, 2, Q as u16 - 1, Q as u16 - 2, 6144, 6145];
        for &a in &samples {
            for &b in &samples {
                let exp_add = ((a as u32) + (b as u32)) % Q;
                let got_add = FieldElement::from_plain(a)
                    .add(FieldElement::from_plain(b))
                    .to_plain();
                assert_eq!(got_add as u32, exp_add, "add mismatch a={a} b={b}");

                let exp_sub = ((a as u32) + Q - (b as u32)) % Q;
                let got_sub = FieldElement::from_plain(a)
                    .sub(FieldElement::from_plain(b))
                    .to_plain();
                assert_eq!(got_sub as u32, exp_sub, "sub mismatch a={a} b={b}");
            }
        }
    }
}
