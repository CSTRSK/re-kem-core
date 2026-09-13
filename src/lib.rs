//! # re-kem-core
//!
//! A constant-time Ring-LWE Key Encapsulation Mechanism — the full Rust port
//! of the Python reference implementation
//! ([RE-KEM](https://github.com/CSTRSK/RE-KEM)).
//!
//! ## Cryptography
//!
//! ```text
//! Ring:     Z_q[X] / (X^n + 1),  q = 12289, eta = 8
//! Sets:     n = 512 (default), n = 1024
//! Security: IND-CCA2 via Fujisaki-Okamoto
//! ```
//!
//! ## Structure
//!
//! The crate separates concerns deliberately:
//!
//! | Module | Responsibility |
//! |--------|----------------|
//! | [`params`] | The parameter sets — the *only* place `n`, `q`, `eta` live |
//! | [`version`] | Algorithm identifiers and self-describing envelopes |
//! | [`api`] | The [`api::Kem`] trait and a runtime [`api::Registry`] |
//! | [`ntt`], [`sampling`], [`kem`] | The arithmetic and the KEM, generic over `n` |
//!
//! ## Two parameter sets
//!
//! ```text
//! ReKem      n=512   pk 1056 B   sk 2144 B   ct 2048 B
//! ReKem1024  n=1024  pk 2080 B   sk 4192 B   ct 4096 B
//! ```
//!
//! Availability of `n = 1024` rests on a **documented error-probability
//! derivation for this crate's zero-padding encoding** (`docs/error-probability.md`)
//! plus byte-level cross-validation against the Python reference at the same
//! dimension — *not* on the published NewHope-1024 analysis, which assumes a
//! 4-fold redundant per-bit encoding. See that document before relying on it.
//!
//! ## Example
//!
//! ```
//! use re_kem_core::ReKem;
//!
//! let kem = ReKem::new();
//! let (pk, sk) = kem.keygen();
//! let (ct, ss_sender) = kem.encaps(&pk);
//! let ss_receiver = kem.decaps(&sk, &ct);
//! assert_eq!(ss_sender, ss_receiver);
//! ```

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

extern crate alloc;

pub mod api;
pub mod field;
pub mod kem;
pub mod ntt;
pub mod params;
pub mod sampling;
pub mod version;

pub use field::{FieldElement, Q};
pub use kem::{
    KemGeneric, ReKem, ReKem1024, CT_LEN, CT_LEN_1024, PK_LEN, PK_LEN_1024, SEED_LEN, SK_LEN,
    SK_LEN_1024, SS_LEN,
};
pub use ntt::{Poly, N};
pub use params::{Params, ACTIVE, LEVEL5_1024, NEWHOPE_512};
pub use sampling::{cbd_sample, expand_a};
pub use version::{Algorithm, Envelope, VersionError};
