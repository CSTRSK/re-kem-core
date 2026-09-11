// no_std for the production target; tests link std so we can use Vec etc.
#![cfg_attr(not(test), no_std)]

pub mod field;

pub use field::{FieldElement, Q};
