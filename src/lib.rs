//! # re-kem-core
//!
//! A constant-time Ring-LWE Key Encapsulation Mechanism — the full Rust port
//! of the Python reference implementation
//! ([RE-KEM](https://github.com/CSTRSK/RE-KEM)).
//!
//! Parameters (NewHope-512 regime): `n = 512`, `q = 12289`, `eta = 8`.
//! Security: IND-CCA2 via the Fujisaki–Okamoto transform with implicit
//! rejection.
//!
//! ```no_run
//! use re_kem_core::ReKem;
//!
//! let kem = ReKem::new();
//! let (pk, sk) = kem.keygen();
//! let (ct, ss_tx) = kem.encaps(&pk);
//! let ss_rx = kem.decaps(&sk, &ct);
//! assert_eq!(ss_tx, ss_rx);
//! ```
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod field;
pub mod kem;
pub mod ntt;
pub mod sampling;

pub use field::{FieldElement, Q};
pub use kem::{ReKem, CT_LEN, PK_LEN, SK_LEN, SS_LEN};
pub use ntt::{NttContext, Poly, N};
pub use sampling::{cbd_sample, decode_poly, encode_poly, expand_a};
