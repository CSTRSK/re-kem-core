//! Hybride KEMs: RE-KEM-512 + X25519 und ML-KEM-768 + X25519.
//!
//! **Experimentell.** Diese Formate sind nicht standardisiert und **nicht**
//! kompatibel zu X-Wing. Der Quantenschutz haengt allein am PQ-Teil; X25519
//! liefert nur klassische Absicherung zusaetzlich. Es liegt kein externes
//! Audit vor.
//!
//! # Aufbau
//!
//! | Objekt | Hybrid A (`0x81`) | Hybrid B (`0x90`) |
//! |---|---|---|
//! | pk | `rekem_pk (1056) || x25519_pk (32)` = 1088 | `mlkem768_ek (1184) || x25519_pk (32)` = 1216 |
//! | sk | `rekem_sk (2144) || x_sk (32) || x_pk (32)` = 2208 | `mlkem768_dk (2400) || x_sk (32) || x_pk (32)` = 2464 |
//! | ct | `rekem_ct (2048) || x_ct (32)` = 2080 | `mlkem768_ct (1088) || x_ct (32)` = 1120 |
//! | ss | 32 | 32 |
//!
//! # Kombinierer
//!
//! ```text
//! ss = SHA3-256("re-kem-core/hybrid/v1" || id || pq_ss || x_ss || pq_ct || x_ct || x_pk)
//! ```

use sha3::{Digest, Sha3_256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::version::Algorithm;
use crate::{CT_LEN, PK_LEN, SK_LEN};

/// Domaenentrennung: 21 Byte ASCII, kein Nullbyte.
const PRAEFIX: &[u8] = b"re-kem-core/hybrid/v1";

/// Laenge des X25519-Anteils in Byte.
pub const X25519_LEN: usize = 32;
/// Laenge des kombinierten Shared Secrets.
pub const HYBRID_SS_LEN: usize = 32;

/// Hybrid A: `rekem_pk || x_pk`.
pub const HYB_REKEM_PK_LEN: usize = PK_LEN + X25519_LEN;
/// Hybrid A: `rekem_sk || x_sk || x_pk`.
pub const HYB_REKEM_SK_LEN: usize = SK_LEN + 2 * X25519_LEN;
/// Hybrid A: `rekem_ct || x_ct`.
pub const HYB_REKEM_CT_LEN: usize = CT_LEN + X25519_LEN;

/// FIPS-203: ML-KEM-768 Encapsulation-Key.
pub const MLKEM768_EK_LEN: usize = 1184;
/// FIPS-203: ML-KEM-768 Decapsulation-Key.
pub const MLKEM768_DK_LEN: usize = 2400;
/// FIPS-203: ML-KEM-768 Chiffretext.
pub const MLKEM768_CT_LEN: usize = 1088;

/// Hybrid B: `mlkem768_ek || x_pk`.
pub const HYB_MLKEM_PK_LEN: usize = MLKEM768_EK_LEN + X25519_LEN;
/// Hybrid B: `mlkem768_dk || x_sk || x_pk`.
pub const HYB_MLKEM_SK_LEN: usize = MLKEM768_DK_LEN + 2 * X25519_LEN;
/// Hybrid B: `mlkem768_ct || x_ct`.
pub const HYB_MLKEM_CT_LEN: usize = MLKEM768_CT_LEN + X25519_LEN;

/// Der Kombinierer. Reihenfolge und Laengen sind verbindlich.
fn kombinierer(
    id: u8,
    pq_ss: &[u8; 32],
    x_ss: &[u8; 32],
    pq_ct: &[u8],
    x_ct: &[u8; 32],
    x_pk: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(PRAEFIX);
    h.update([id]);
    h.update(pq_ss);
    h.update(x_ss);
    h.update(pq_ct);
    h.update(x_ct);
    h.update(x_pk);
    h.finalize().into()
}

/// Fuer die Known-Answer-Tests: Kombinierer direkt aufrufbar.
#[doc(hidden)]
pub fn kombinierer_oeffentlich(
    id: u8,
    pq_ss: &[u8; 32],
    x_ss: &[u8; 32],
    pq_ct: &[u8],
    x_ct: &[u8; 32],
    x_pk: &[u8; 32],
) -> [u8; 32] {
    kombinierer(id, pq_ss, x_ss, pq_ct, x_ct, x_pk)
}

/// Fuellt einen Puffer mit Betriebssystem-Zufall.
#[cfg(feature = "rng")]
fn zufall(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("OS randomness unavailable");
}

/// Oeffentlichen X25519-Schluessel aus einem geheimen ableiten.
fn x_pk_aus(x_sk: &[u8; 32]) -> [u8; 32] {
    let geheim = StaticSecret::from(*x_sk);
    PublicKey::from(&geheim).to_bytes()
}

/// Rohes X25519-DH. Liefert das Ergebnis auch, wenn es komplett Null ist.
fn x_dh(eigen_sk: &[u8; 32], fremd_pk: &[u8; 32]) -> ([u8; 32], bool) {
    let geheim = StaticSecret::from(*eigen_sk);
    let oeffentlich = PublicKey::from(*fremd_pk);
    let gemeinsam = geheim.diffie_hellman(&oeffentlich);
    let beitragend = gemeinsam.was_contributory();
    (*gemeinsam.as_bytes(), beitragend)
}

// ═══════════════════════ Hybrid A: RE-KEM-512 + X25519 ═══════════════════════

/// Hybrid aus RE-KEM-512 (n = 512) und X25519.
#[cfg(feature = "hybrid-rekem-x25519")]
#[derive(Debug, Default, Clone, Copy)]
pub struct HybridReKem512X25519;

#[cfg(feature = "hybrid-rekem-x25519")]
impl HybridReKem512X25519 {
    /// Algorithmus-Kennung dieses Hybrids.
    pub const ID: u8 = Algorithm::HybridReKem512X25519 as u8;

    /// Erzeugt ein Schluesselpaar (deterministisch).
    pub fn keygen_derand(
        &self,
        sa: &[u8; 32],
        ns: &[u8; 32],
        z: &[u8; 32],
        x_sk: &[u8; 32],
    ) -> ([u8; HYB_REKEM_PK_LEN], [u8; HYB_REKEM_SK_LEN]) {
        use crate::kem::KemGeneric;

        let kem = KemGeneric::<512, PK_LEN, SK_LEN, CT_LEN>::new();
        let (pq_pk, pq_sk) = kem.keygen_derand(sa, ns, z);
        let x_pk = x_pk_aus(x_sk);

        let mut pk = [0u8; HYB_REKEM_PK_LEN];
        pk[..PK_LEN].copy_from_slice(&pq_pk);
        pk[PK_LEN..].copy_from_slice(&x_pk);

        let mut sk = [0u8; HYB_REKEM_SK_LEN];
        sk[..SK_LEN].copy_from_slice(&pq_sk);
        sk[SK_LEN..SK_LEN + X25519_LEN].copy_from_slice(x_sk);
        sk[SK_LEN + X25519_LEN..].copy_from_slice(&x_pk);

        (pk, sk)
    }

    /// Erzeugt ein Schluesselpaar mit Zufall.
    #[cfg(feature = "rng")]
    pub fn keygen(&self) -> ([u8; HYB_REKEM_PK_LEN], [u8; HYB_REKEM_SK_LEN]) {
        let mut buf = [0u8; 4 * 32];
        zufall(&mut buf);
        let mut sa = [0u8; 32];
        let mut ns = [0u8; 32];
        let mut z = [0u8; 32];
        let mut x_sk = [0u8; 32];
        sa.copy_from_slice(&buf[..32]);
        ns.copy_from_slice(&buf[32..64]);
        z.copy_from_slice(&buf[64..96]);
        x_sk.copy_from_slice(&buf[96..]);
        self.keygen_derand(&sa, &ns, &z, &x_sk)
    }

    /// Kapselt. Liefert `None` bei Punkt kleiner Ordnung im pk.
    pub fn encaps_derand(
        &self,
        pk: &[u8; HYB_REKEM_PK_LEN],
        m: &[u8; 32],
        e_sk: &[u8; 32],
    ) -> Option<([u8; HYB_REKEM_CT_LEN], [u8; HYBRID_SS_LEN])> {
        use crate::kem::KemGeneric;

        let (pq_pk, x_pk) = pk.split_at(PK_LEN);
        let x_pk: [u8; 32] = x_pk.try_into().ok()?;
        let pq_pk: [u8; PK_LEN] = pq_pk.try_into().ok()?;

        let kem = KemGeneric::<512, PK_LEN, SK_LEN, CT_LEN>::new();
        let (pq_ct, pq_ss) = kem.encaps_derand(&pq_pk, m);

        let x_ct = x_pk_aus(e_sk);
        let (x_ss, beitragend) = x_dh(e_sk, &x_pk);
        if !beitragend {
            return None;
        }

        let ss = kombinierer(Self::ID, &pq_ss, &x_ss, &pq_ct, &x_ct, &x_pk);

        let mut ct = [0u8; HYB_REKEM_CT_LEN];
        ct[..CT_LEN].copy_from_slice(&pq_ct);
        ct[CT_LEN..].copy_from_slice(&x_ct);

        Some((ct, ss))
    }

    /// Entkapselt. Bei X25519-Ergebnis Null wird bewusst weitergerechnet.
    pub fn decaps(
        &self,
        sk: &[u8; HYB_REKEM_SK_LEN],
        ct: &[u8; HYB_REKEM_CT_LEN],
    ) -> [u8; HYBRID_SS_LEN] {
        use crate::kem::KemGeneric;

        let (pq_sk, rest) = sk.split_at(SK_LEN);
        let (x_sk, x_pk) = rest.split_at(X25519_LEN);
        let pq_sk: [u8; SK_LEN] = pq_sk.try_into().unwrap_or([0u8; SK_LEN]);
        let x_sk: [u8; 32] = x_sk.try_into().unwrap_or([0u8; 32]);
        let x_pk: [u8; 32] = x_pk.try_into().unwrap_or([0u8; 32]);

        let (pq_ct, x_ct) = ct.split_at(CT_LEN);
        let pq_ct: [u8; CT_LEN] = pq_ct.try_into().unwrap_or([0u8; CT_LEN]);
        let x_ct: [u8; 32] = x_ct.try_into().unwrap_or([0u8; 32]);

        let kem = KemGeneric::<512, PK_LEN, SK_LEN, CT_LEN>::new();
        let pq_ss = kem.decaps(&pq_sk, &pq_ct);

        let (x_ss, _) = x_dh(&x_sk, &x_ct);

        kombinierer(Self::ID, &pq_ss, &x_ss, &pq_ct, &x_ct, &x_pk)
    }
}

// ═══════════════════════ Hybrid B: ML-KEM-768 + X25519 ═══════════════════════

/// Hybrid aus ML-KEM-768 (FIPS 203) und X25519.
#[cfg(feature = "hybrid-mlkem-x25519")]
#[derive(Debug, Default, Clone, Copy)]
pub struct HybridMlKem768X25519;

#[cfg(feature = "hybrid-mlkem-x25519")]
impl HybridMlKem768X25519 {
    /// Algorithmus-Kennung dieses Hybrids.
    pub const ID: u8 = Algorithm::HybridMlKem768X25519 as u8;

    /// Erzeugt ein Schluesselpaar (deterministisch).
    pub fn keygen_derand(
        &self,
        pq_seed: &[u8; 64],
        x_sk: &[u8; 32],
    ) -> ([u8; HYB_MLKEM_PK_LEN], [u8; HYB_MLKEM_SK_LEN]) {
        use ml_kem::kem::KeyExport;
        use ml_kem::ExpandedKeyEncoding;
        use ml_kem::{DecapsulationKey, MlKem768, Seed};

        let dk = DecapsulationKey::<MlKem768>::from(Seed::from(*pq_seed));
        let ek = dk.encapsulation_key();
        // ek.to_bytes() liefert den 1184-Byte-Encapsulation-Key.
        let ek_bytes = ek.to_bytes();
        // dk.to_bytes() waere nur der 64-Byte-Seed; die 2400 Byte liegen im
        // expanded Format.
        let dk_bytes = dk.to_expanded_bytes();
        let x_pk = x_pk_aus(x_sk);

        let mut pk = [0u8; HYB_MLKEM_PK_LEN];
        pk[..MLKEM768_EK_LEN].copy_from_slice(ek_bytes.as_slice());
        pk[MLKEM768_EK_LEN..].copy_from_slice(&x_pk);

        let mut sk = [0u8; HYB_MLKEM_SK_LEN];
        sk[..MLKEM768_DK_LEN].copy_from_slice(dk_bytes.as_slice());
        sk[MLKEM768_DK_LEN..MLKEM768_DK_LEN + X25519_LEN].copy_from_slice(x_sk);
        sk[MLKEM768_DK_LEN + X25519_LEN..].copy_from_slice(&x_pk);

        (pk, sk)
    }

    /// Erzeugt ein Schluesselpaar mit Zufall.
    #[cfg(feature = "rng")]
    pub fn keygen(&self) -> ([u8; HYB_MLKEM_PK_LEN], [u8; HYB_MLKEM_SK_LEN]) {
        let mut pq_seed = [0u8; 64];
        let mut x_sk = [0u8; 32];
        zufall(&mut pq_seed);
        zufall(&mut x_sk);
        self.keygen_derand(&pq_seed, &x_sk)
    }

    /// Kapselt. Liefert `None` bei Punkt kleiner Ordnung im pk.
    pub fn encaps_derand(
        &self,
        pk: &[u8; HYB_MLKEM_PK_LEN],
        m: &[u8; 32],
        e_sk: &[u8; 32],
    ) -> Option<([u8; HYB_MLKEM_CT_LEN], [u8; HYBRID_SS_LEN])> {
        use ml_kem::kem::{Encapsulate, KeyExport};
        use ml_kem::{B32, EncapsulationKey, Key, MlKem768};

        let (ek_bytes, x_pk) = pk.split_at(MLKEM768_EK_LEN);
        let x_pk: [u8; 32] = x_pk.try_into().ok()?;

        let ek_array: [u8; MLKEM768_EK_LEN] = ek_bytes.try_into().ok()?;
        let ek_buf = Key::<EncapsulationKey<MlKem768>>::from(ek_array);
        let ek = EncapsulationKey::<MlKem768>::new(&ek_buf).ok()?;

        let (pq_ct, pq_ss) = ek.encapsulate_deterministic(&B32::from(*m));
        let pq_ss_bytes: [u8; 32] = pq_ss.as_slice().try_into().ok()?;

        let x_ct = x_pk_aus(e_sk);
        let (x_ss, beitragend) = x_dh(e_sk, &x_pk);
        if !beitragend {
            return None;
        }

        let ss = kombinierer(Self::ID, &pq_ss_bytes, &x_ss, &pq_ct, &x_ct, &x_pk);

        let mut ct = [0u8; HYB_MLKEM_CT_LEN];
        ct[..MLKEM768_CT_LEN].copy_from_slice(&pq_ct);
        ct[MLKEM768_CT_LEN..].copy_from_slice(&x_ct);

        Some((ct, ss))
    }

    /// Entkapselt. Bei X25519-Ergebnis Null wird bewusst weitergerechnet.
    pub fn decaps(
        &self,
        sk: &[u8; HYB_MLKEM_SK_LEN],
        ct: &[u8; HYB_MLKEM_CT_LEN],
    ) -> [u8; HYBRID_SS_LEN] {
        use ml_kem::kem::Decapsulate;
        use ml_kem::ExpandedKeyEncoding;
        use ml_kem::{Ciphertext, DecapsulationKey, MlKem768};

        let (dk_bytes, rest) = sk.split_at(MLKEM768_DK_LEN);
        let (x_sk, x_pk) = rest.split_at(X25519_LEN);
        let x_sk: [u8; 32] = x_sk.try_into().unwrap_or([0u8; 32]);
        let x_pk: [u8; 32] = x_pk.try_into().unwrap_or([0u8; 32]);

        let (pq_ct, x_ct) = ct.split_at(MLKEM768_CT_LEN);
        let x_ct: [u8; 32] = x_ct.try_into().unwrap_or([0u8; 32]);

        let mut pq_ss_bytes = [0u8; 32];
        if let Ok(dk_array) = <[u8; MLKEM768_DK_LEN]>::try_from(dk_bytes) {
            // Aus dem expanded Format (2400 Byte) rekonstruieren; die Crate
            // prueft dabei die Konsistenz von ek und h.
            let expanded = ml_kem::ExpandedDecapsulationKey::<MlKem768>::from(dk_array);
            if let Ok(dk) = DecapsulationKey::<MlKem768>::from_expanded_bytes(&expanded) {
                if let Ok(ct_array) = <&Ciphertext<MlKem768>>::try_from(pq_ct) {
                    let pq_ss = dk.decapsulate(ct_array);
                    if let Ok(b) = <[u8; 32]>::try_from(pq_ss.as_slice()) {
                        pq_ss_bytes = b;
                    }
                }
            }
        }

        let (x_ss, _) = x_dh(&x_sk, &x_ct);

        kombinierer(Self::ID, &pq_ss_bytes, &x_ss, pq_ct, &x_ct, &x_pk)
    }
}
