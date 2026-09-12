//! The KEM interface — what makes RE-KEM swappable without touching callers.
//!
//! The point of a trait here is **not** abstraction for its own sake. It is
//! that a caller should be able to hold `Box<dyn Kem>`, read the algorithm
//! from configuration, and later switch to a second parameter set, a hybrid,
//! or ML-KEM without editing the code that stores keys or moves ciphertexts.
//!
//! The interface is deliberately **object-safe** (no associated types, no
//! generics in the signature): `dyn Kem` is exactly what a runtime algorithm
//! choice needs. Sizes are queried, never hard-coded by callers.
//!
//! Nothing in this module implements cryptography. It forwards to
//! [`crate::kem::ReKem`], which is unchanged.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use crate::params::Params;
use crate::version::Algorithm;

/// Byte lengths of the objects an implementation produces.
///
/// Callers allocate from this, so a parameter-set change does not require
/// recompiling the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sizes {
    pub public_key: usize,
    pub secret_key: usize,
    pub ciphertext: usize,
    pub shared_secret: usize,
}

/// Failures a KEM implementation may report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KemError {
    /// Buffer did not have the length the implementation expects.
    BadLength {
        what: &'static str,
        expected: usize,
        got: usize,
    },
    /// The algorithm is registered but not enabled in this build.
    NotEnabled(Algorithm),
    /// Randomness source failed.
    Randomness,
    /// The algorithm exists but is not implemented here at all.
    UnknownAlgorithm(Algorithm),
}

impl core::fmt::Display for KemError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            KemError::BadLength { what, expected, got } => {
                write!(f, "{what}: expected {expected} bytes, got {got}")
            }
            KemError::NotEnabled(a) => {
                write!(f, "{} is not enabled in this build", a.label())
            }
            KemError::Randomness => write!(f, "randomness source failed"),
            KemError::UnknownAlgorithm(a) => write!(f, "{} is not implemented", a.label()),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for KemError {}

/// A key pair returned by [`Kem::keygen`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

/// A key encapsulation mechanism, as seen by calling code.
///
/// Implementations must be usable from multiple threads (`Send + Sync`)
/// because a service may encapsulate concurrently.
pub trait Kem: Send + Sync {
    /// Which wire-format identifier this implementation writes.
    fn algorithm(&self) -> Algorithm;

    /// Object sizes for allocation.
    fn sizes(&self) -> Sizes;

    /// Generate a fresh key pair.
    fn keygen(&self) -> Result<KeyPair, KemError>;

    /// Encapsulate to a public key, returning `(ciphertext, shared_secret)`.
    fn encaps(&self, public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), KemError>;

    /// Recover the shared secret. Implementations must return an error or a
    /// pseudo-random secret for tampered input — never the real secret.
    fn decaps(&self, secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, KemError>;

    /// Human-readable name, for logs and metrics.
    fn name(&self) -> &'static str;
}

// ─────────────────────────────────────────────────────────────────────────
// Adapter: the existing RE-KEM behind the trait.
// ─────────────────────────────────────────────────────────────────────────

use crate::kem::ReKem;

/// RE-KEM behind [`Kem`].
///
/// It is a thin forwarder: `keygen`/`encaps`/`decaps` call exactly the same
/// routines as before, so byte-for-byte behaviour is unchanged and the Python
/// cross-validation still applies.
pub struct ReKemKem {
    inner: ReKem,
    params: Params,
}

impl ReKemKem {
    /// Build an adapter for the compiled-in parameter set.
    pub fn new() -> Self {
        ReKemKem {
            inner: ReKem::new(),
            params: crate::params::ACTIVE,
        }
    }

    /// The parameter set this adapter was built with.
    pub fn params(&self) -> Params {
        self.params
    }
}

impl Default for ReKemKem {
    fn default() -> Self {
        Self::new()
    }
}

impl Kem for ReKemKem {
    fn algorithm(&self) -> Algorithm {
        Algorithm::ReKem512
    }

    fn sizes(&self) -> Sizes {
        Sizes {
            public_key: self.params.pk_len(),
            secret_key: self.params.sk_len(),
            ciphertext: self.params.ct_len(),
            shared_secret: self.params.ss_len,
        }
    }

    fn keygen(&self) -> Result<KeyPair, KemError> {
        let (pk, sk) = self.inner.keygen();
        Ok(KeyPair {
            public_key: pk.to_vec(),
            secret_key: sk.to_vec(),
        })
    }

    fn encaps(&self, public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), KemError> {
        let want = self.params.pk_len();
        if public_key.len() != want {
            return Err(KemError::BadLength {
                what: "public key",
                expected: want,
                got: public_key.len(),
            });
        }
        let mut pk = [0u8; crate::kem::PK_LEN];
        pk.copy_from_slice(public_key);
        let (ct, ss) = self.inner.encaps(&pk);
        Ok((ct.to_vec(), ss.to_vec()))
    }

    fn decaps(&self, secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, KemError> {
        let want_sk = self.params.sk_len();
        if secret_key.len() != want_sk {
            return Err(KemError::BadLength {
                what: "secret key",
                expected: want_sk,
                got: secret_key.len(),
            });
        }
        let want_ct = self.params.ct_len();
        if ciphertext.len() != want_ct {
            return Err(KemError::BadLength {
                what: "ciphertext",
                expected: want_ct,
                got: ciphertext.len(),
            });
        }
        let mut sk = [0u8; crate::kem::SK_LEN];
        sk.copy_from_slice(secret_key);
        let mut ct = [0u8; crate::kem::CT_LEN];
        ct.copy_from_slice(ciphertext);
        let ss = self.inner.decaps(&sk, &ct);
        Ok(ss.to_vec())
    }

    fn name(&self) -> &'static str {
        "re-kem"
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Registry: choose an implementation at runtime by name or id.
// ─────────────────────────────────────────────────────────────────────────

/// Maps algorithm identifiers to implementations.
///
/// This is the piece that turns "we should support ML-KEM one day" into a
/// configuration change: a caller asks the registry for an algorithm by id
/// and gets whatever implementation is wired in, without knowing which.
pub struct Registry {
    entries: Vec<(Algorithm, Box<dyn Kem>)>,
}

impl Registry {
    /// An empty registry.
    pub fn new() -> Self {
        Registry {
            entries: Vec::new(),
        }
    }

    /// The registry as shipped: everything enabled in this build.
    pub fn with_defaults() -> Self {
        let mut r = Registry::new();
        r.register(Box::new(ReKemKem::new()));
        r
    }

    /// Add an implementation. Later registrations of the same algorithm
    /// replace earlier ones, which is how a test or a migration path swaps in
    /// an alternative without changing call sites.
    pub fn register(&mut self, kem: Box<dyn Kem>) {
        let alg = kem.algorithm();
        self.entries.retain(|(a, _)| *a != alg);
        self.entries.push((alg, kem));
    }

    /// Look up by wire-format identifier.
    pub fn get(&self, algorithm: Algorithm) -> Option<&dyn Kem> {
        self.entries
            .iter()
            .find(|(a, _)| *a == algorithm)
            .map(|(_, k)| k.as_ref())
    }

    /// Look up by stable label, e.g. `"re-kem-512"`. Useful when the
    /// algorithm comes from a config file.
    pub fn get_by_label(&self, label: &str) -> Option<&dyn Kem> {
        self.entries
            .iter()
            .find(|(_, k)| k.name() == label || k.algorithm().label() == label)
            .map(|(_, k)| k.as_ref())
    }

    /// All registered algorithms, in registration order.
    pub fn algorithms(&self) -> Vec<Algorithm> {
        self.entries.iter().map(|(a, _)| *a).collect()
    }

    /// Labels for diagnostics.
    pub fn labels(&self) -> Vec<String> {
        self.entries
            .iter()
            .map(|(a, _)| String::from(a.label()))
            .collect()
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trait_adapter_matches_the_inherent_api() {
        let kem = ReKemKem::new();
        let inner = ReKem::new();
        assert_eq!(kem.sizes().public_key, crate::kem::PK_LEN);
        assert_eq!(kem.sizes().secret_key, crate::kem::SK_LEN);
        assert_eq!(kem.sizes().ciphertext, crate::kem::CT_LEN);
        assert_eq!(kem.sizes().shared_secret, crate::kem::SS_LEN);
        let _ = inner; // both exist; no behaviour change
    }

    #[test]
    fn roundtrip_through_the_trait() {
        let kem = ReKemKem::new();
        let kp = kem.keygen().unwrap();
        let (ct, ss1) = kem.encaps(&kp.public_key).unwrap();
        let ss2 = kem.decaps(&kp.secret_key, &ct).unwrap();
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn works_as_a_trait_object() {
        // The whole point: a caller can hold dyn Kem and not know which.
        let boxed: Box<dyn Kem> = Box::new(ReKemKem::new());
        let kp = boxed.keygen().unwrap();
        let (ct, ss1) = boxed.encaps(&kp.public_key).unwrap();
        assert_eq!(boxed.decaps(&kp.secret_key, &ct).unwrap(), ss1);
        assert_eq!(boxed.algorithm(), Algorithm::ReKem512);
    }

    #[test]
    fn wrong_lengths_are_rejected() {
        let kem = ReKemKem::new();
        assert!(matches!(
            kem.encaps(&[0u8; 10]),
            Err(KemError::BadLength { what: "public key", .. })
        ));
    }

    #[test]
    fn registry_lookup_by_id_and_label() {
        let r = Registry::with_defaults();
        assert!(r.get(Algorithm::ReKem512).is_some());
        assert!(r.get_by_label("re-kem-512").is_some());
        assert!(r.get(Algorithm::MlKem768).is_none());
        // The registry does not invent implementations for reserved ids.
        assert_eq!(r.algorithms(), alloc::vec![Algorithm::ReKem512]);
    }
}
