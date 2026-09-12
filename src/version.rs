//! Algorithm registry and versioned wire formats.
//!
//! The raw byte strings produced by the KEM (`pk`, `sk`, `ct`) are unchanged —
//! they are what the Python reference cross-validates against, and changing
//! them would break that check for no benefit. Instead this module adds a
//! **self-describing envelope** for storage and transport:
//!
//! ```text
//! [ alg_id : 1 byte ][ body_len : 4 bytes BE ][ body ]
//! ```
//!
//! That one byte is what makes a later migration cheap: a stored key or
//! ciphertext says which algorithm produced it, so a reader can route it to
//! the right implementation instead of guessing from the length.
//!
//! Length-prefixing matters for the same reason: `n = 512` and `n = 1024`
//! produce different sizes today, but a future scheme could coincidentally
//! match, and guessing from length is exactly the kind of implicit coupling
//! that makes migrations expensive.

use alloc::vec::Vec;

/// Identifiers for every KEM that may appear in a stored or transmitted
/// object. Values are **permanent** — never reuse or renumber one, or old
/// data becomes ambiguous.
///
/// The high nibble groups families, the low nibble is the variant:
///
/// | Range  | Family |
/// |--------|--------|
/// | `0x0_` | RE-KEM (this crate) |
/// | `0x1_` | ML-KEM (FIPS 203) |
/// | `0x2_` | Classical |
/// | `0x8_`–`0x9_` | Hybrids (both components present) |
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Algorithm {
    /// RE-KEM, `n = 512`, q = 12289, eta = 8. The current default.
    ReKem512 = 0x01,
    /// RE-KEM, `n = 1024`. Reserved: sizes known, arithmetic untested,
    /// **not** offered until cross-validated. See `docs/deprecation-policy.md`.
    ReKem1024 = 0x02,

    /// ML-KEM-768 (FIPS 203) — the standardised migration target.
    MlKem768 = 0x10,
    /// ML-KEM-1024 (FIPS 203).
    MlKem1024 = 0x11,

    /// X25519 as a standalone KEM (RFC 7748 + HKDF).
    X25519 = 0x20,

    /// Hybrid RE-KEM-512 + X25519, combined per the `LabeledHKDF`
    /// construction of draft-irtf-cfrg-hybrid-kems.
    HybridReKem512X25519 = 0x81,
    /// Hybrid ML-KEM-768 + X25519 (the deployed TLS 1.3 shape).
    HybridMlKem768X25519 = 0x90,
}

impl Algorithm {
    /// The byte written to the wire.
    pub const fn id(self) -> u8 {
        self as u8
    }

    /// Whether this algorithm is currently offered to callers.
    ///
    /// Reserved identifiers exist so a future build can recognise data it
    /// cannot yet process — that is the difference between "unknown format"
    /// and "known format, this build is too old", which is the difference
    /// between a silent failure and a clear error.
    pub const fn is_offered(self) -> bool {
        matches!(self, Algorithm::ReKem512 | Algorithm::HybridReKem512X25519)
    }

    /// Decode an identifier byte.
    ///
    /// Returns `None` for unknown values rather than panicking: a reader
    /// must be able to reject data from a newer writer cleanly.
    pub const fn from_id(id: u8) -> Option<Self> {
        match id {
            0x01 => Some(Algorithm::ReKem512),
            0x02 => Some(Algorithm::ReKem1024),
            0x10 => Some(Algorithm::MlKem768),
            0x11 => Some(Algorithm::MlKem1024),
            0x20 => Some(Algorithm::X25519),
            0x81 => Some(Algorithm::HybridReKem512X25519),
            0x90 => Some(Algorithm::HybridMlKem768X25519),
            _ => None,
        }
    }

    /// Short stable label for diagnostics and metrics.
    pub const fn label(self) -> &'static str {
        match self {
            Algorithm::ReKem512 => "re-kem-512",
            Algorithm::ReKem1024 => "re-kem-1024",
            Algorithm::MlKem768 => "ml-kem-768",
            Algorithm::MlKem1024 => "ml-kem-1024",
            Algorithm::X25519 => "x25519",
            Algorithm::HybridReKem512X25519 => "hybrid-re-kem-512+x25519",
            Algorithm::HybridMlKem768X25519 => "hybrid-ml-kem-768+x25519",
        }
    }
}

/// Errors from envelope decoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VersionError {
    /// Fewer than 5 bytes — no header to read.
    Truncated,
    /// The declared body length does not match the bytes present.
    LengthMismatch { declared: u32, actual: usize },
    /// The identifier byte is not in the registry.
    UnknownAlgorithm(u8),
    /// The identifier is known but this build does not offer it.
    NotOffered(Algorithm),
    /// Body length would overflow the platform's `usize`.
    LengthOverflow(u32),
}

impl core::fmt::Display for VersionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VersionError::Truncated => write!(f, "envelope shorter than the 5-byte header"),
            VersionError::LengthMismatch { declared, actual } => write!(
                f,
                "declared body length {declared} but {actual} bytes follow"
            ),
            VersionError::UnknownAlgorithm(id) => {
                write!(f, "unknown algorithm id {id:#04x} (data from a newer format?)")
            }
            VersionError::NotOffered(a) => write!(
                f,
                "algorithm {} is known but not enabled in this build",
                a.label()
            ),
            VersionError::LengthOverflow(n) => write!(f, "body length {n} exceeds usize"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for VersionError {}

/// A wrapped byte string whose algorithm is recorded alongside it.
///
/// Used for every object that outlives a single process: public keys, secret
/// keys, ciphertexts, and hybrid components.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    algorithm: Algorithm,
    body: Vec<u8>,
}

impl Envelope {
    /// Wrap a raw body.
    pub fn new(algorithm: Algorithm, body: Vec<u8>) -> Self {
        Envelope { algorithm, body }
    }

    /// The algorithm that produced the body.
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// The raw body (what the KEM itself produces).
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Consume the envelope, yielding the raw body.
    pub fn into_body(self) -> Vec<u8> {
        self.body
    }

    /// Total encoded length: 1 byte id + 4 bytes length + body.
    pub fn encoded_len(&self) -> usize {
        5 + self.body.len()
    }

    /// Serialise to `[id][len BE][body]`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        out.push(self.algorithm.id());
        out.extend_from_slice(&(self.body.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.body);
        out
    }

    /// Parse `[id][len BE][body]`.
    ///
    /// Rejects unknown identifiers, unknown-but-declared lengths, and
    /// truncated input. Does **not** check that the body has the length the
    /// algorithm implies — that belongs to the KEM implementation, which
    /// knows the parameter set.
    pub fn decode(bytes: &[u8]) -> Result<Self, VersionError> {
        if bytes.len() < 5 {
            return Err(VersionError::Truncated);
        }
        let id = bytes[0];
        let algorithm = Algorithm::from_id(id).ok_or(VersionError::UnknownAlgorithm(id))?;

        let declared = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
        let body = &bytes[5..];
        if declared as usize != body.len() {
            return Err(VersionError::LengthMismatch {
                declared,
                actual: body.len(),
            });
        }
        Ok(Envelope {
            algorithm,
            body: body.to_vec(),
        })
    }

    /// Parse and additionally require that the algorithm is offered by this
    /// build.
    pub fn decode_supported(bytes: &[u8]) -> Result<Self, VersionError> {
        let env = Self::decode(bytes)?;
        if !env.algorithm.is_offered() {
            return Err(VersionError::NotOffered(env.algorithm));
        }
        Ok(env)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn roundtrip() {
        let env = Envelope::new(Algorithm::ReKem512, vec![1, 2, 3, 4]);
        let bytes = env.encode();
        assert_eq!(bytes[0], 0x01);
        assert_eq!(&bytes[1..5], &[0, 0, 0, 4]);
        assert_eq!(Envelope::decode(&bytes).unwrap(), env);
    }

    #[test]
    fn ids_are_stable_and_unique() {
        // Guards against someone renumbering: stored data depends on these.
        let all = [
            Algorithm::ReKem512,
            Algorithm::ReKem1024,
            Algorithm::MlKem768,
            Algorithm::MlKem1024,
            Algorithm::X25519,
            Algorithm::HybridReKem512X25519,
            Algorithm::HybridMlKem768X25519,
        ];
        let mut seen = alloc::vec::Vec::new();
        for a in all {
            assert!(!seen.contains(&a.id()), "duplicate id for {}", a.label());
            seen.push(a.id());
            assert_eq!(Algorithm::from_id(a.id()), Some(a), "id roundtrip {}", a.label());
        }
    }

    #[test]
    fn unknown_id_is_rejected_not_panicked() {
        let bytes = [0xFE, 0, 0, 0, 0];
        assert_eq!(
            Envelope::decode(&bytes),
            Err(VersionError::UnknownAlgorithm(0xFE))
        );
    }

    #[test]
    fn reserved_algorithm_parses_but_is_not_offered() {
        // A newer writer may produce n=1024 data. An older reader must
        // recognise it and say so, rather than reporting a corrupt blob.
        let env = Envelope::new(Algorithm::ReKem1024, vec![0u8; 16]);
        let bytes = env.encode();
        assert!(Envelope::decode(&bytes).is_ok());
        assert_eq!(
            Envelope::decode_supported(&bytes),
            Err(VersionError::NotOffered(Algorithm::ReKem1024))
        );
        assert!(!Algorithm::ReKem1024.is_offered());
    }

    #[test]
    fn truncated_and_mismatched_are_rejected() {
        assert_eq!(Envelope::decode(&[0x01, 0, 0]), Err(VersionError::Truncated));
        let bad = [0x01, 0, 0, 0, 9, 1, 2];
        assert_eq!(
            Envelope::decode(&bad),
            Err(VersionError::LengthMismatch { declared: 9, actual: 2 })
        );
    }
}
