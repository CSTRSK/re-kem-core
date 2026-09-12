//! # re-kem-core
//!
//! A constant-time Ring-LWE Key Encapsulation Mechanism — the full Rust port
//! of the Python reference implementation
//! ([RE-KEM](https://github.com/CSTRSK/RE-KEM)).
//!
//! ## Cryptography
//!
//! ```text
//! Ring:    Z_q[X] / (X^n + 1),  n = 512, q = 12289, eta = 8
//! Security: IND-CCA2 via Fujisaki-Okamoto
//! ```
//!
//! ## Structure
//!
//! The crate separates three concerns deliberately:
//!
//! | Module | Responsibility |
//! |--------|----------------|
//! | [`params`] | The parameter set — the *only* place `n`, `q`, `eta` live |
//! | [`version`] | Algorithm identifiers and self-describing envelopes |
//! | [`api`] | The [`api::Kem`] trait and a runtime [`api::Registry`] |
//!
//! The cryptographic core ([`field`], [`ntt`], [`sampling`], [`kem`]) is
//! unchanged and cross-validated byte-for-byte against the Python reference.
//! The three modules above add no mathematics — they make a later change of
//! parameters or algorithm cheap, which is a different problem from making
//! the current one stronger.
//!
//! ## Example
//!
//! ```
//! use re_kem_core::{api::{Kem, KeyPair}, ReKem};
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
pub use kem::{ReKem, CT_LEN, PK_LEN, SEED_LEN, SK_LEN, SS_LEN};
pub use ntt::{Poly, N};
pub use params::{Params, ACTIVE, LEVEL5_1024, NEWHOPE_512};
pub use sampling::{cbd_sample, expand_a};
pub use version::{Algorithm, Envelope, VersionError};
