//! Tests für die Hybrid-KEMs (RE-KEM-512 + X25519, ML-KEM-768 + X25519).
//!
//! Läuft nur mit aktivem Feature. Beide Algorithmen werden mit denselben
//! Prüfungen abgedeckt; die algorithmusspezifischen Unterschiede stecken in
//! den Modulen `a` und `b`.

#![cfg(any(feature = "hybrid-rekem-x25519", feature = "hybrid-mlkem-x25519"))]

use re_kem_core::version::Algorithm;

/// Im Debug-Profil weniger Wiederholungen als im Release-Profil.
fn skaliert(release: usize, debug: usize) -> usize {
    if cfg!(debug_assertions) {
        debug
    } else {
        release
    }
}

fn hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    let b = s.as_bytes();
    assert_eq!(b.len(), 64, "erwartet 64 Hex-Zeichen");
    for i in 0..32 {
        let hi = (b[2 * i] as char).to_digit(16).expect("hex");
        let lo = (b[2 * i + 1] as char).to_digit(16).expect("hex");
        out[i] = ((hi << 4) | lo) as u8;
    }
    out
}

/// Deterministische Seed-Folge für einen Zähler.
fn seed_bytes(n: u64, len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(len);
    let mut x = n.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(1);
    for _ in 0..len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        v.push((x & 0xFF) as u8);
    }
    v
}

// ═══════════════════════ hyb04: Kombinierer gegen Python ═══════════════════

/// Vektoren aus `tools/hybrid_referenz.py` (hashlib.sha3_256), fest eingebettet.
/// Die Eingaben werden im Test mit derselben Formel erzeugt wie dort.
const KAT: [(u8, &str); 20] = [
    (0x81, "120068aa3d3c14d66342eafffa5d5d2261570bfe34628f89c05cad1a7edc848f"),
    (0x90, "582776f99925acdb01d81173241ccb5a6a4a0aad8fa9d1a2e89a9a27b9711771"),
    (0x81, "fb467d8af2ed3696eeb429a1e94c1a7b04b200724b65e92b00cd3f75cf6751d8"),
    (0x90, "1b0d24eb51d2fc24d61a30be55bb3f978db6e9d60c683862d58e6dfa0a295db2"),
    (0x81, "1fe56c450f6b6378ab6a86b772bcde9d185bc5a1463d67efa878b24985bdd082"),
    (0x90, "280166921ee396200978acf2c033c2f4033cce496cee48ab05a55518fe91e761"),
    (0x81, "872afd99f6beaa373d7943d1df4dd45f07b7bf60d12a5cac95222f9ef9a6dc01"),
    (0x90, "ca0d76af84e21ab789fdf4634e435ece61563ec7fc52e9500c46237db99d42d8"),
    (0x81, "c0e40d31bab7c1165609f5bc43ddf20ca191aa6517d15dab84d881f26bdc8c95"),
    (0x90, "1d8614c662b6ed3d354baf572e24bf6e21fcc8481866a1f21e4dbf29712ee88d"),
    (0x81, "631f9e05a7a1a13e16283b59ba5264dcaa6fa6ada9fbc7444797620a6d1e7e32"),
    (0x90, "484fba70904f58e83e1d51c780bbf7cbe0af83e125dd6bfa4c07d5f15efc02d7"),
    (0x81, "4a8824046ef81212ba16d4b494ae9ebf3307d0c60610b06cdc0bdcb3c6037fcd"),
    (0x90, "e4f6ca0e4c5ddb0f79cc143edae727fa12bdfb8b5b5da349ddc17d1bcf767a3e"),
    (0x81, "dc319b32400fef683bd6158ac551264a9c73c3f47627e4a4958d49bf93813128"),
    (0x90, "c7803fd4331b9756c6f10cb5e36fab93ddf2618be06bad1613030fde5554fe1b"),
    (0x81, "ef1187f98faf9e440838bb908bb3c9074429c66f5006e5d9a91ac36e57ee3528"),
    (0x90, "8ada36d33e3b0df7e69747fa1cffaf5d3f77a5c04912337ce6886deebee0473c"),
    (0x81, "9878118922e685940aecdebbe5bab52e40360528bd755e2acce4789e810f560c"),
    (0x90, "6db8dab5f80c21cf4352b13e3668075a56455aac060048413ababd5d8f877c65"),
];

#[test]
fn hyb04_kombinierer_gegen_python_referenz() {
    use re_kem_core::hybrid::kombinierer_oeffentlich;

    for (i, (id, erwartet)) in KAT.iter().enumerate() {
        // Gleiche Formel wie tools/hybrid_referenz.py
        let mut pq_ss = [0u8; 32];
        for (j, byte) in pq_ss.iter_mut().enumerate() {
            *byte = ((i * 7 + j) % 256) as u8;
        }
        let mut x_ss = [0u8; 32];
        for (j, byte) in x_ss.iter_mut().enumerate() {
            *byte = ((i * 13 + j) % 256) as u8;
        }
        let pq_ct_len = if *id == 0x81 { 2048 } else { 1088 };
        let pq_ct: Vec<u8> = (0..pq_ct_len).map(|j| ((i * 3 + j) % 256) as u8).collect();
        let mut x_ct = [0u8; 32];
        for (j, byte) in x_ct.iter_mut().enumerate() {
            *byte = ((i * 11 + j) % 256) as u8;
        }
        let mut x_pk = [0u8; 32];
        for (j, byte) in x_pk.iter_mut().enumerate() {
            *byte = ((i * 17 + j) % 256) as u8;
        }

        let ist = kombinierer_oeffentlich(*id, &pq_ss, &x_ss, &pq_ct, &x_ct, &x_pk);
        let soll = hex32(erwartet);
        assert_eq!(
            ist, soll,
            "Vektor {i} (id 0x{id:02x}) weicht von der Python-Referenz ab"
        );
    }
}

// ═════════════════ hyb05: X25519 gegen RFC 7748 (wörtlich) ═════════════════

#[test]
fn hyb05_x25519_rfc7748_testvektoren() {
    use x25519_dalek::{PublicKey, StaticSecret};

    // Abschnitt 5.2 des RFC 7748 — wörtlich übernommen.
    let faelle = [
        (
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
        ),
        (
            "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
            "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
        ),
    ];
    for (sk_hex, pk_hex, soll_hex) in faelle {
        let sk = StaticSecret::from(hex32(sk_hex));
        let pk = PublicKey::from(hex32(pk_hex));
        let gemeinsam = sk.diffie_hellman(&pk);
        assert_eq!(
            *gemeinsam.as_bytes(),
            hex32(soll_hex),
            "RFC-7748-Vektor weicht ab"
        );
    }

    // Abschnitt 6.1: das Diffie-Hellman-Beispiel.
    let a_privat = hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let a_oeffentlich = hex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    let b_privat = hex32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    let b_oeffentlich = hex32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let gemeinsam_soll = hex32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    let a = StaticSecret::from(a_privat);
    let b = StaticSecret::from(b_privat);

    // Öffentliche Schlüssel müssen aus den privaten ableitbar sein.
    assert_eq!(PublicKey::from(&a).to_bytes(), a_oeffentlich, "Alice pk");
    assert_eq!(PublicKey::from(&b).to_bytes(), b_oeffentlich, "Bob pk");

    // Beide Richtungen ergeben dasselbe Geheimnis.
    let ab = a.diffie_hellman(&PublicKey::from(b_oeffentlich));
    let ba = b.diffie_hellman(&PublicKey::from(a_oeffentlich));
    assert_eq!(*ab.as_bytes(), gemeinsam_soll, "Alice-Seite");
    assert_eq!(*ba.as_bytes(), gemeinsam_soll, "Bob-Seite");
}

// ═════════════════ Algorithmusspezifische Hilfsschicht ═════════════════

/// Einheitliche Schnittstelle, damit dieselben Tests beide Hybride abdecken.
#[cfg(feature = "hybrid-rekem-x25519")]
mod a {
    use crate::Algorithm;
    use re_kem_core::hybrid::*;

    pub const PK: usize = HYB_REKEM_PK_LEN;
    pub const SK: usize = HYB_REKEM_SK_LEN;
    pub const CT: usize = HYB_REKEM_CT_LEN;
    pub const SS: usize = HYBRID_SS_LEN;
    pub const ID: u8 = Algorithm::HybridReKem512X25519 as u8;

    pub fn keygen(seed: u64) -> (Vec<u8>, Vec<u8>) {
        let sa = crate::seed_bytes(seed, 32);
        let ns = crate::seed_bytes(seed.wrapping_add(1), 32);
        let z = crate::seed_bytes(seed.wrapping_add(2), 32);
        let x = crate::seed_bytes(seed.wrapping_add(3), 32);
        let sa: [u8; 32] = sa.try_into().unwrap();
        let ns: [u8; 32] = ns.try_into().unwrap();
        let z: [u8; 32] = z.try_into().unwrap();
        let x: [u8; 32] = x.try_into().unwrap();
        let (pk, sk) = HybridReKem512X25519.keygen_derand(&sa, &ns, &z, &x);
        (pk.to_vec(), sk.to_vec())
    }

    pub fn encaps(pk: &[u8], seed: u64) -> Option<(Vec<u8>, Vec<u8>)> {
        if pk.len() != PK {
            return None;
        }
        let p: [u8; PK] = pk.try_into().ok()?;
        let m: [u8; 32] = crate::seed_bytes(seed.wrapping_add(10), 32)
            .try_into()
            .ok()?;
        let e: [u8; 32] = crate::seed_bytes(seed.wrapping_add(11), 32)
            .try_into()
            .ok()?;
        HybridReKem512X25519
            .encaps_derand(&p, &m, &e)
            .map(|(ct, ss)| (ct.to_vec(), ss.to_vec()))
    }

    pub fn decaps(sk: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
        if sk.len() != SK || ct.len() != CT {
            return None;
        }
        let s: [u8; SK] = sk.try_into().ok()?;
        let c: [u8; CT] = ct.try_into().ok()?;
        Some(HybridReKem512X25519.decaps(&s, &c).to_vec())
    }

}

#[cfg(feature = "hybrid-mlkem-x25519")]
mod b {
    use crate::Algorithm;
    use re_kem_core::hybrid::*;

    pub const PK: usize = HYB_MLKEM_PK_LEN;
    pub const SK: usize = HYB_MLKEM_SK_LEN;
    pub const CT: usize = HYB_MLKEM_CT_LEN;
    pub const SS: usize = HYBRID_SS_LEN;
    pub const ID: u8 = Algorithm::HybridMlKem768X25519 as u8;

    pub fn keygen(seed: u64) -> (Vec<u8>, Vec<u8>) {
        let pq = crate::seed_bytes(seed, 64);
        let x = crate::seed_bytes(seed.wrapping_add(3), 32);
        let pq: [u8; 64] = pq.try_into().unwrap();
        let x: [u8; 32] = x.try_into().unwrap();
        let (pk, sk) = HybridMlKem768X25519.keygen_derand(&pq, &x);
        (pk.to_vec(), sk.to_vec())
    }

    pub fn encaps(pk: &[u8], seed: u64) -> Option<(Vec<u8>, Vec<u8>)> {
        if pk.len() != PK {
            return None;
        }
        let p: [u8; PK] = pk.try_into().ok()?;
        let m: [u8; 32] = crate::seed_bytes(seed.wrapping_add(10), 32)
            .try_into()
            .ok()?;
        let e: [u8; 32] = crate::seed_bytes(seed.wrapping_add(11), 32)
            .try_into()
            .ok()?;
        HybridMlKem768X25519
            .encaps_derand(&p, &m, &e)
            .map(|(ct, ss)| (ct.to_vec(), ss.to_vec()))
    }

    pub fn decaps(sk: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
        if sk.len() != SK || ct.len() != CT {
            return None;
        }
        let s: [u8; SK] = sk.try_into().ok()?;
        let c: [u8; CT] = ct.try_into().ok()?;
        Some(HybridMlKem768X25519.decaps(&s, &c).to_vec())
    }

}

// ══════════════ Makro: dieselben Tests für beide Algorithmen ══════════════

macro_rules! hybrid_tests {
    ($mod_name:ident, $m:path, $alg:expr, $andere:expr) => {
        mod $mod_name {
            use super::*;
            use $m as h;

            /// hyb01: Größen exakt wie in der Spezifikation.
            #[test]
            fn hyb01_groessen() {
                let (pk, sk) = h::keygen(1);
                assert_eq!(pk.len(), h::PK, "pk-Laenge");
                assert_eq!(sk.len(), h::SK, "sk-Laenge");
                let (ct, ss) = h::encaps(&pk, 2).expect("encaps");
                assert_eq!(ct.len(), h::CT, "ct-Laenge");
                assert_eq!(ss.len(), h::SS, "ss-Laenge");
            }

            /// hyb02: Rundreise.
            #[test]
            fn hyb02_rundreise() {
                let runden = skaliert(200, 20);
                for i in 0..runden {
                    let (pk, sk) = h::keygen(1000 + i as u64);
                    let (ct, ss) = h::encaps(&pk, 2000 + i as u64).expect("encaps");
                    let ss2 = h::decaps(&sk, &ct).expect("decaps");
                    assert_eq!(ss, ss2, "Runde {i}: Rundreise fehlgeschlagen");
                }
            }

            /// hyb03: Determinismus.
            #[test]
            fn hyb03_determinismus() {
                let (pk1, sk1) = h::keygen(7);
                let (pk2, sk2) = h::keygen(7);
                assert_eq!(pk1, pk2, "keygen nicht deterministisch (pk)");
                assert_eq!(sk1, sk2, "keygen nicht deterministisch (sk)");

                let (ct1, ss1) = h::encaps(&pk1, 8).expect("encaps 1");
                let (ct2, ss2) = h::encaps(&pk1, 8).expect("encaps 2");
                assert_eq!(ct1, ct2, "encaps nicht deterministisch (ct)");
                assert_eq!(ss1, ss2, "encaps nicht deterministisch (ss)");

                // Andere Seeds muessen abweichen.
                let (pk3, _) = h::keygen(9);
                assert_ne!(pk1, pk3, "verschiedene Seeds liefern gleichen pk");
                let (ct3, ss3) = h::encaps(&pk1, 99).expect("encaps 3");
                assert_ne!(ct1, ct3, "verschiedene Nachrichten liefern gleichen ct");
                assert_ne!(ss1, ss3, "verschiedene Nachrichten liefern gleiches ss");
            }

            /// hyb06: Manipulation im PQ-Teil.
            #[test]
            fn hyb06_manipulation_pq_teil() {
                let (pk, sk) = h::keygen(20);
                let (ct, ss) = h::encaps(&pk, 21).expect("encaps");

                let pq_ct_len = if h::ID == 0x81 { 2048 } else { 1088 };
                let mut schlecht = 0;
                for pruefung in 0..skaliert(64, 8) {
                    let bit = (pruefung * 37 + 11) % (pq_ct_len * 8);
                    let mut c = ct.clone();
                    c[bit / 8] ^= 1 << (bit % 8);
                    if c == ct {
                        continue;
                    }
                    let ss2 = h::decaps(&sk, &c).expect("decaps darf nicht paniken");
                    if ss2 != ss {
                        schlecht += 1;
                    }
                }
                assert_eq!(
                    schlecht,
                    skaliert(64, 8),
                    "manipuliertes pq_ct ergab das echte Secret"
                );
            }

            /// hyb07: Manipulation im X25519-Teil (alle 256 Bits).
            #[test]
            fn hyb07_manipulation_x_teil() {
                let (pk, sk) = h::keygen(30);
                let (ct, ss) = h::encaps(&pk, 31).expect("encaps");

                for bit in 0..256 {
                    let mut c = ct.clone();
                    // x_ct liegt am Ende des Chiffretexts
                    let pos = ct.len() - 32 + bit / 8;
                    c[pos] ^= 1 << (bit % 8);
                    let ss2 = h::decaps(&sk, &c).expect("decaps darf nicht paniken");
                    assert_ne!(ss2, ss, "x_ct-Bit {bit} ohne Wirkung auf das Secret");
                }
            }

            /// hyb08: Mix-and-Match.
            #[test]
            fn hyb08_mix_and_match() {
                let (pk, sk) = h::keygen(40);
                let (ct1, ss1) = h::encaps(&pk, 41).expect("encaps 1");
                let (ct2, ss2) = h::encaps(&pk, 42).expect("encaps 2");
                assert_ne!(ss1, ss2);

                // pq_ct aus Lauf 1, x_ct aus Lauf 2.
                let trenn = ct1.len() - 32;
                let mut gemischt = Vec::new();
                gemischt.extend_from_slice(&ct1[..trenn]);
                gemischt.extend_from_slice(&ct2[trenn..]);

                let ss_gemischt = h::decaps(&sk, &gemischt).expect("decaps");
                assert_ne!(ss_gemischt, ss1, "Mix-and-Match ergab Secret 1");
                assert_ne!(ss_gemischt, ss2, "Mix-and-Match ergab Secret 2");
            }

            /// hyb09: Schlüsselbindung an x_pk.
            #[test]
            fn hyb09_schluesselbindung() {
                let (pk, sk) = h::keygen(50);
                let (ct, ss_echt) = h::encaps(&pk, 51).expect("encaps");

                // x_pk im pk durch einen anderen ersetzen.
                let mut pk2 = pk.clone();
                let x_pk_pos = pk.len() - 32;
                for i in 0..32 {
                    pk2[x_pk_pos + i] ^= 0xA5;
                }
                if let Some((ct2, ss2)) = h::encaps(&pk2, 51) {
                    assert_ne!(ss2, ss_echt, "manipulierter x_pk ergab das echte Secret");
                    // Der Halter des Original-sk bekommt nicht das Secret des Angreifers.
                    let ss_halter = h::decaps(&sk, &ct2).expect("decaps");
                    assert_ne!(ss_halter, ss2, "Halter erhaelt das Angreifer-Secret");
                }
                // Das echte Secret bleibt unberuehrt.
                assert_eq!(h::decaps(&sk, &ct).expect("decaps"), ss_echt);
            }

            /// hyb10: Punkt kleiner Ordnung + Null-Chiffretext.
            #[test]
            fn hyb10_kleine_ordnung() {
                let (pk, _sk) = h::keygen(60);

                // x_pk = 32 Nullbytes: encaps muss InvalidPublicKey liefern.
                let mut pk_null = pk.clone();
                let x_pk_pos = pk.len() - 32;
                for i in 0..32 {
                    pk_null[x_pk_pos + i] = 0;
                }
                assert!(
                    h::encaps(&pk_null, 61).is_none(),
                    "x_pk aus Nullbytes wurde akzeptiert ({})", $alg.label()
                );

                // decaps mit x_ct = 32 Nullbytes: kein Panik, deterministisch.
                let (_pk2, sk2) = h::keygen(62);
                let mut ct_null = vec![0u8; h::CT];
                let trenn = h::CT - 32;
                for i in 0..trenn {
                    ct_null[i] = (i % 251) as u8;
                }
                let a = h::decaps(&sk2, &ct_null).expect("decaps darf nicht paniken");
                let b = h::decaps(&sk2, &ct_null).expect("decaps darf nicht paniken");
                assert_eq!(a, b, "decaps mit Null-x_ct nicht deterministisch");
            }

            /// hyb11: Längenfehler.
            #[test]
            fn hyb11_laengenfehler() {
                let (pk, sk) = h::keygen(70);
                let (ct, _) = h::encaps(&pk, 71).expect("encaps");

                // encaps mit falscher pk-Laenge
                assert!(h::encaps(&[], 72).is_none());
                assert!(h::encaps(&pk[..pk.len() - 1], 72).is_none());
                let mut zu_lang = pk.clone();
                zu_lang.push(0);
                assert!(h::encaps(&zu_lang, 72).is_none());

                // decaps mit falscher sk- oder ct-Laenge
                assert!(h::decaps(&[], &ct).is_none());
                assert!(h::decaps(&sk[..sk.len() - 1], &ct).is_none());
                assert!(h::decaps(&sk, &[]).is_none());
                assert!(h::decaps(&sk, &ct[..ct.len() - 1]).is_none());
                let mut ct_lang = ct.clone();
                ct_lang.push(0);
                assert!(h::decaps(&sk, &ct_lang).is_none());
            }

            /// hyb12: Totalität bei beliebigen Eingaben.
            #[test]
            fn hyb12_totalitaet() {
                let (pk, _sk) = h::keygen(80);
                let (ct, _) = h::encaps(&pk, 81).expect("encaps");

                let mus = [
                    vec![0u8; h::SK],
                    vec![0xFFu8; h::SK],
                    seed_bytes(90, h::SK),
                ];
                let cts = [
                    vec![0u8; h::CT],
                    vec![0xFFu8; h::CT],
                    seed_bytes(91, h::CT),
                    ct.clone(),
                ];

                for (i, s) in mus.iter().enumerate() {
                    for (j, c) in cts.iter().enumerate() {
                        let a = h::decaps(s, c).expect("decaps darf nicht paniken");
                        let b = h::decaps(s, c).expect("decaps darf nicht paniken");
                        assert_eq!(a, b, "sk {i}/ct {j} nicht deterministisch");
                        assert_eq!(a.len(), h::SS);
                    }
                }

                // encaps gegen Null- und 0xFF-pk darf nicht paniken.
                let _ = h::encaps(&vec![0u8; h::PK], 92);
                let _ = h::encaps(&vec![0xFFu8; h::PK], 93);
            }

            /// hyb14: keine Vermischung — ein pk des anderen Hybrids wird
            /// abgelehnt, weil die Laengen nicht passen (1088 vs 1216).
            #[test]
            fn hyb14_keine_vermischung() {
                let (pk, sk) = h::keygen(100);
                let (ct, ss) = h::encaps(&pk, 101).expect("eigener pk");

                // Der eigene pk funktioniert.
                assert_eq!(h::decaps(&sk, &ct).expect("eigener ct"), ss);

                // Ein pk mit der Laenge des anderen Hybrids muss abgelehnt
                // werden: die Laengenpruefung greift vor allem anderen.
                let fremde_laenge = if h::ID == 0x81 {
                    1216 // ML-KEM-768-Hybrid
                } else {
                    1088 // RE-KEM-512-Hybrid
                };
                assert_ne!(fremde_laenge, h::PK, "Laengen duerfen sich nicht gleichen");
                let fremd_pk = vec![0xAAu8; fremde_laenge];
                assert!(
                    h::encaps(&fremd_pk, 102).is_none(),
                    "pk des anderen Hybrids wurde akzeptiert"
                );

                // Dasselbe fuer sk und ct in decaps.
                let fremd_sk_len = if h::ID == 0x81 { 2464 } else { 2208 };
                let fremd_sk = vec![0xAAu8; fremd_sk_len];
                assert!(
                    h::decaps(&fremd_sk, &ct).is_none(),
                    "sk des anderen Hybrids wurde akzeptiert"
                );

                let fremd_ct_len = if h::ID == 0x81 { 1120 } else { 2080 };
                let fremd_ct = vec![0xAAu8; fremd_ct_len];
                assert!(
                    h::decaps(&sk, &fremd_ct).is_none(),
                    "ct des anderen Hybrids wurde akzeptiert"
                );

                // Die IDs bleiben verschieden (Formalismus, aber billig).
                assert_eq!(h::ID, $alg as u8);
                assert_ne!(h::ID, $andere as u8);
            }

            /// hyb13 (Teil): Registry-Zugriff.
            #[test]
            fn hyb13_registry_zugriff() {
                use re_kem_core::api::Registry;
                let reg = Registry::with_defaults();
                let kem = reg.get($alg).expect("Algorithmus nicht in der Registry");
                assert_eq!(kem.name(), $alg.label());

                let kp = kem.keygen().expect("keygen");
                assert_eq!(kp.public_key.len(), h::PK);
                assert_eq!(kp.secret_key.len(), h::SK);
                let (ct, ss) = kem.encaps(&kp.public_key).expect("encaps");
                assert_eq!(ct.len(), h::CT);
                assert_eq!(kem.decaps(&kp.secret_key, &ct).expect("decaps"), ss);
            }
        }
    };
}

#[cfg(feature = "hybrid-rekem-x25519")]
hybrid_tests!(
    tests_a,
    crate::a,
    Algorithm::HybridReKem512X25519,
    Algorithm::HybridMlKem768X25519
);

#[cfg(feature = "hybrid-mlkem-x25519")]
hybrid_tests!(
    tests_b,
    crate::b,
    Algorithm::HybridMlKem768X25519,
    Algorithm::HybridReKem512X25519
);

// ═══════════════ hyb13: Registry ohne Features nicht registriert ═══════════

#[test]
fn hyb13_registry_ohne_feature_nicht_registriert() {
    use re_kem_core::api::Registry;

    let reg = Registry::with_defaults();

    // Immer vorhanden:
    assert!(reg.get(Algorithm::ReKem512).is_some());
    assert!(reg.get(Algorithm::ReKem1024).is_some());

    // Feature-abhängig:
    #[cfg(feature = "hybrid-rekem-x25519")]
    assert!(reg.get(Algorithm::HybridReKem512X25519).is_some());
    #[cfg(not(feature = "hybrid-rekem-x25519"))]
    assert!(reg.get(Algorithm::HybridReKem512X25519).is_none());

    #[cfg(feature = "hybrid-mlkem-x25519")]
    assert!(reg.get(Algorithm::HybridMlKem768X25519).is_some());
    #[cfg(not(feature = "hybrid-mlkem-x25519"))]
    assert!(reg.get(Algorithm::HybridMlKem768X25519).is_none());

    // is_offered muss mit der Registry übereinstimmen.
    for alg in [Algorithm::HybridReKem512X25519, Algorithm::HybridMlKem768X25519] {
        assert_eq!(
            alg.is_offered(),
            reg.get(alg).is_some(),
            "is_offered und Registry widersprechen sich fuer {}",
            alg.label()
        );
    }
}

// ═══════════════════════ hyb15: ML-KEM-768-Größen ═══════════════════════

#[cfg(feature = "hybrid-mlkem-x25519")]
#[test]
fn hyb15_mlkem768_groessen_gegen_das_crate() {
    use ml_kem::kem::KeyExport;
    #[allow(deprecated)]
    use ml_kem::ExpandedKeyEncoding;
    use ml_kem::{DecapsulationKey, MlKem768, Seed};
    use re_kem_core::hybrid::{MLKEM768_CT_LEN, MLKEM768_DK_LEN, MLKEM768_EK_LEN};

    let dk = DecapsulationKey::<MlKem768>::from(Seed::from([3u8; 64]));
    let ek = dk.encapsulation_key();

    assert_eq!(ek.to_bytes().len(), MLKEM768_EK_LEN, "ek-Groesse");
    #[allow(deprecated)]
    let dk_len = dk.to_expanded_bytes().len();
    assert_eq!(dk_len, MLKEM768_DK_LEN, "dk-Groesse");

    // Rundreise des PQ-Teils allein (deterministisch).
    use ml_kem::B32;
    let m = B32::from([9u8; 32]);
    let (ct, ss) = ek.encapsulate_deterministic(&m);
    assert_eq!(ct.len(), MLKEM768_CT_LEN, "ct-Groesse");

    use ml_kem::kem::Decapsulate;
    let ss2 = dk.decapsulate(&ct);
    assert_eq!(ss, ss2, "ML-KEM-768-Rundreise fehlgeschlagen");
}

// ═══════════ hyb14: keine Vermischung zwischen den Hybriden ═══════════

#[cfg(all(feature = "hybrid-rekem-x25519", feature = "hybrid-mlkem-x25519"))]
#[test]
fn hyb14_hybride_lassen_sich_nicht_vermischen() {
    use re_kem_core::api::{KemError, Registry};

    let reg = Registry::with_defaults();
    let ka = reg.get(Algorithm::HybridReKem512X25519).expect("A");
    let kb = reg.get(Algorithm::HybridMlKem768X25519).expect("B");

    let kpa = ka.keygen().expect("keygen A");
    let kpb = kb.keygen().expect("keygen B");

    // pk von A an B: Laengenfehler, kein Panik.
    assert!(matches!(
        kb.encaps(&kpa.public_key),
        Err(KemError::BadLength {
            what: "public key",
            ..
        })
    ));
    assert!(matches!(
        ka.encaps(&kpb.public_key),
        Err(KemError::BadLength {
            what: "public key",
            ..
        })
    ));

    // Chiffretext von A an B.
    let (ct_a, _) = ka.encaps(&kpa.public_key).expect("encaps A");
    assert!(matches!(
        kb.decaps(&kpb.secret_key, &ct_a),
        Err(KemError::BadLength {
            what: "ciphertext",
            ..
        })
    ));

    // sk von A an B.
    assert!(matches!(
        kb.decaps(&kpa.secret_key, &ct_a),
        Err(KemError::BadLength {
            what: "secret key",
            ..
        })
    ));
}
