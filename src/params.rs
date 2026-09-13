//! Parameter sets — the single source of truth for (n, q, eta) and every
//! derived size.
//!
//! Before this module the parameters were spread across four files:
//! `Q`/`Q_INV_NEG`/`R2_MOD_Q` in `field.rs`, `N` in `ntt.rs`, `ETA` in
//! `sampling.rs`, and the byte sizes in `kem.rs`. Swapping the parameter set
//! meant touching all four and hoping nothing was missed.
//!
//! Now a set is described once by [`Params`], and the modules read from it.
//! The constants `N`, `Q` and `ETA` still exist as re-exports so that existing
//! code (and the byte-identical Python cross-validation) is unaffected.
//!
//! Nothing here changes the cryptography — only where the numbers live.

/// A complete parameter set for the ring `Z_q[X]/(X^n + 1)` with CBD noise.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// Polynomial degree / torus dimension.
    pub n: usize,
    /// NTT-friendly prime modulus.
    pub q: u32,
    /// CBD noise parameter (coefficients are drawn from `[-eta, eta]`).
    pub eta: usize,
    /// Length of the seeds used for `a(x)` expansion and noise sampling.
    pub seed_len: usize,
    /// Length of the shared secret in bytes.
    pub ss_len: usize,
    /// Human-readable name, used in diagnostics and the algorithm registry.
    pub name: &'static str,
    /// `true` if this set uses parameters with a published cryptanalysis.
    pub analysed: bool,
}

impl Params {
    /// 2 bytes per coefficient.
    pub const fn poly_len(&self) -> usize {
        2 * self.n
    }

    /// `seed_a || b(x)`
    pub const fn pk_len(&self) -> usize {
        self.seed_len + self.poly_len()
    }

    /// `s(x) || pk || H(pk) || z`
    pub const fn sk_len(&self) -> usize {
        self.poly_len() + self.pk_len() + 32 + self.seed_len
    }

    /// `u(x) || v(x)`
    pub const fn ct_len(&self) -> usize {
        2 * self.poly_len()
    }

    /// Number of bits a message carries (`seed_len * 8`).
    pub const fn msg_bits(&self) -> usize {
        self.seed_len * 8
    }

    /// Bytes produced per CBD coefficient (`2*eta` bits).
    pub const fn cbd_bytes(&self) -> usize {
        (2 * self.eta * self.n + 7) / 8
    }

    /// Upper rejection bound for uniform expansion of `a(x)`:
    /// `floor(2^16 / q) * q`. Drawn 16-bit words below this are accepted.
    pub const fn rejection_limit(&self) -> u32 {
        (0x10000 / self.q) * self.q
    }

    /// Rejection rate of the sampler, in percent (informational).
    pub fn rejection_rate_pct(&self) -> f64 {
        100.0 * (1.0 - (self.rejection_limit() as f64) / 65536.0)
    }
}

/// **The parameter set in use.** Matches the published NewHope-512 regime
/// (Alkim/Ducas/Poeppelmann/Schwabe 2016, tight-bound refinement
/// Plantard et al. eprint 2019/1451).
///
/// This is the set every byte in the current wire format is built from.
pub const NEWHOPE_512: Params = Params {
    n: 512,
    q: 12289,
    eta: 8,
    seed_len: 32,
    ss_len: 32,
    name: "RE-KEM n=512 (NewHope-512 regime)",
    analysed: true,
};

/// **Second parameter set: `n = 1024`.**
///
/// `q = 12289` is NTT-friendly up to `n = 4096` (`q − 1 = 12288 = 2¹² · 3`, so
/// a primitive `2n`-th root of unity exists for every power of two up to
/// 4096), so no new arithmetic primitive is needed — the same code runs with
/// larger tables.
///
/// **Basis for offering it:** the failure probability of *this crate's*
/// encoding at this dimension is derived in `docs/error-probability.md` from
/// the noise model (upper bound ≈ 5.96e−57 per round, ≈ 2⁻¹⁸⁷), and the
/// implementation is byte-identical to the Python reference over 1000 rounds
/// at `n = 1024`.
///
/// **This does not inherit the NewHope-1024 analysis.** That work assumes a
/// 4-fold redundant per-bit encoding; this crate zero-pads. The distinction is
/// the reason `analysed` is a per-set field rather than a property of the
/// parameter triple, and why the derivation above was required before the set
/// could be marked analysed.
pub const LEVEL5_1024: Params = Params {
    n: 1024,
    q: 12289,
    eta: 8,
    seed_len: 32,
    ss_len: 32,
    name: "RE-KEM n=1024",
    analysed: true,
};

/// The parameter set compiled into this build.
pub const ACTIVE: Params = NEWHOPE_512;
