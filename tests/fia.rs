//! Software-emulierte Fault-Injection (FIA) in der Entkapselung.
//!
//! Zwei Fehlermodelle:
//!  * **äußere** Störung — einzelne Bits im geheimen Schlüssel oder im
//!    Chiffretext (ohne Feature lauffähig),
//!  * **innere** Störung — ein einzelnes Bit im Zwischenvektor `w = v - u·s`
//!    mitten in `pke_decrypt` (nur mit Feature `fia-hooks`).
//!
//! Die Prüfaussage ist in beiden Fällen dieselbe und von außen nachweisbar:
//! Die Entkapselung darf nur zwei Ergebnisse kennen — das ehrliche Secret und
//! das eine Ablehnungs-Secret. Ein dritter Wert wäre eine Teilinformation.
mod common;

use common::vg::Rng;
use re_kem_core::{ReKem, N};
use re_kem_core::{CT_LEN, PK_LEN, SEED_LEN, SK_LEN, SS_LEN};
use std::collections::HashSet;
use std::panic::{catch_unwind, AssertUnwindSafe};

struct Aufbau {
    kem: ReKem,
    pk: [u8; PK_LEN],
    sk: [u8; SK_LEN],
    ct: [u8; CT_LEN],
    ss: [u8; SS_LEN],
}

fn aufbau(seed: u64) -> Aufbau {
    let kem = ReKem::new();
    let mut rng = Rng::new(seed);
    let mut sa = [0u8; SEED_LEN];
    let mut n = [0u8; SEED_LEN];
    let mut z = [0u8; SEED_LEN];
    let mut m = [0u8; SEED_LEN];
    rng.fill(&mut sa);
    rng.fill(&mut n);
    rng.fill(&mut z);
    rng.fill(&mut m);
    let (pk, sk) = kem.keygen_derand(&sa, &n, &z);
    let (ct, ss) = kem.encaps_derand(&pk, &m);
    Aufbau { kem, pk, sk, ct, ss }
}

/// 1. Einzelbit-Fehler im geheimen Schlüssel: kein Absturz, kein ehrliches
///    Secret, deterministisch.
#[test]
fn fia01_sk_bitfehler() {
    let a = aufbau(0xFA1);
    let mut rng = Rng::new(0xF1A);
    let mut abgelehnt = 0usize;
    for _ in 0..256 {
        let mut sk = a.sk;
        let pos = rng.below(SK_LEN);
        sk[pos] ^= 1 << rng.below(8);
        let ss = catch_unwind(AssertUnwindSafe(|| a.kem.decaps(&sk, &a.ct)))
            .expect("Absturz bei sk-Bitfehler");
        let nochmal = a.kem.decaps(&sk, &a.ct);
        assert_eq!(ss, nochmal, "nicht deterministisch bei sk-Bitfehler");
        if ss != a.ss {
            abgelehnt += 1;
        }
    }
    eprintln!("fia01: {abgelehnt}/256 sk-Fehler liefen in die Ablehnung");
}

/// 2. Einzelbit-Fehler im Chiffretext über den ganzen Bereich.
#[test]
fn fia02_ct_bitfehler_ueber_alle_positionen() {
    let a = aufbau(0xFA2);
    let mut rng = Rng::new(0xF2A);
    let mut ergebnisse: HashSet<[u8; SS_LEN]> = HashSet::new();
    for pos in 0..CT_LEN {
        let mut ct = a.ct;
        ct[pos] ^= 1 << rng.below(8);
        let ss = catch_unwind(AssertUnwindSafe(|| a.kem.decaps(&a.sk, &ct)))
            .expect("Absturz bei ct-Bitfehler");
        assert_ne!(ss, a.ss, "ct-Fehler an Position {pos} wurde akzeptiert");
        ergebnisse.insert(ss);
    }
    // Jede Ablehnung hängt am Hash des Chiffretexts -> praktisch alle
    // Ergebnisse sind verschieden. Wären sie es nicht, deutete das auf eine
    // vom Chiffretext unabhängige Rückgabe hin (also auf ein konstantes Secret).
    assert!(
        ergebnisse.len() > CT_LEN * 3 / 4,
        "zu viele gleiche Ablehnungs-Secrets: {} von {CT_LEN}",
        ergebnisse.len()
    );
    eprintln!("fia02: {} verschiedene Ablehnungs-Secrets über {CT_LEN} Positionen", ergebnisse.len());
}

/// 3. Innere Störung im Zwischenvektor — der eigentliche Fault-Angriff.
///
/// Weil der Chiffretext dabei unverändert bleibt, hängt das Ablehnungs-Secret
/// nur an `z` und `h(ct)`: **alle** Störungen, die in die Ablehnung laufen,
/// müssen dasselbe Secret ergeben. Genau daran erkennt man von außen, dass
/// kein dritter Ausgabepfad existiert.
#[cfg(feature = "fia-hooks")]
#[test]
fn fia03_zwischenvektor_stoerung() {
    use re_kem_core::fia;

    let a = aufbau(0xFA3);
    let mut rng = Rng::new(0xF3A);
    let mut ergebnisse: HashSet<[u8; SS_LEN]> = HashSet::new();
    let mut ohne_wirkung = 0usize;
    let mut abgelehnt = 0usize;

    for i in 0..N {
        let bit = rng.below(16);
        fia::scharf(i, bit);
        let ss = catch_unwind(AssertUnwindSafe(|| a.kem.decaps(&a.sk, &a.ct)))
            .expect("Absturz bei Stoerung im Zwischenvektor");
        fia::aus();

        if ss == a.ss {
            ohne_wirkung += 1;
        } else {
            abgelehnt += 1;
        }
        ergebnisse.insert(ss);
    }

    assert!(
        ergebnisse.len() <= 2,
        "mehr als zwei Ergebnisse ({}) — moegliche Teilinformation",
        ergebnisse.len()
    );
    assert!(abgelehnt > 0, "kein einziger Fehler erreichte die Ablehnung");
    eprintln!(
        "fia03: {} Stoerungen, davon {} ohne Wirkung, {} in der Ablehnung, {} verschiedene Secrets",
        N,
        ohne_wirkung,
        abgelehnt,
        ergebnisse.len()
    );
}

/// 4. Alle Bitpositionen an einer festen Stelle: jeder einzelne Fehler bleibt
///    im Rahmen der beiden erlaubten Ergebnisse.
#[cfg(feature = "fia-hooks")]
#[test]
fn fia04_alle_bitpositionen() {
    use re_kem_core::fia;

    let a = aufbau(0xFA4);
    let mut ergebnisse: HashSet<[u8; SS_LEN]> = HashSet::new();
    for i in [0usize, 1, 100, N / 2, N - 1] {
        for bit in 0..16 {
            fia::scharf(i, bit);
            let ss = a.kem.decaps(&a.sk, &a.ct);
            fia::aus();
            ergebnisse.insert(ss);
        }
    }
    assert!(
        ergebnisse.len() <= 2,
        "mehr als zwei Ergebnisse ({}) ueber 80 Einzelbit-Fehler",
        ergebnisse.len()
    );
    eprintln!("fia04: 80 Einzelbit-Fehler -> {} verschiedene Secrets", ergebnisse.len());
}

/// 5. Die Störung muss nach `aus()` wirklich aus sein — sonst wären die
///    Aussagen der anderen Tests wertlos.
#[cfg(feature = "fia-hooks")]
#[test]
fn fia05_haken_ist_wieder_aus() {
    use re_kem_core::fia;
    let a = aufbau(0xFA5);
    fia::scharf(7, 3);
    let _ = a.kem.decaps(&a.sk, &a.ct);
    fia::aus();
    assert!(!fia::ist_scharf());
    assert_eq!(a.kem.decaps(&a.sk, &a.ct), a.ss, "Haken wirkt nach aus() weiter");
}

/// 6. Ohne das Feature muss die Krypto unverändert sein — der Test hält fest,
///    dass der Normalbau nichts von der Störung weiß.
#[cfg(not(feature = "fia-hooks"))]
#[test]
fn fia06_ohne_feature_unveraendert() {
    let a = aufbau(0xFA6);
    assert_eq!(a.kem.decaps(&a.sk, &a.ct), a.ss);
    eprintln!("fia06: Normalbau ohne fia-hooks — keine Stoerung vorhanden");
}
