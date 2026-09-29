//! IND-CCA2 und Implicit Rejection.
//!
//! Geprüft wird das Verhalten bei manipulierten Chiffretexten: kein Absturz,
//! kein Fehlerobjekt, das etwas verrät, sondern ein deterministisches
//! Pseudozufalls-Secret (Ablehnung über den Zweitschlüssel z).
//!
//! Die Ablehnung selbst ist von außen sichtbar: das Secret hängt dann nur noch
//! von `z` und dem Hash des Chiffretexts ab, nicht mehr von der Nachricht.
mod common;

use common::vg::Rng;
use re_kem_core::{ReKem, CT_LEN, PK_LEN, SEED_LEN, SK_LEN, SS_LEN};
use std::panic::{catch_unwind, AssertUnwindSafe};

struct Aufbau {
    kem: ReKem,
    pk: [u8; PK_LEN],
    sk: [u8; SK_LEN],
    ct: [u8; CT_LEN],
    ss: [u8; SS_LEN],
    m: [u8; SEED_LEN],
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
    Aufbau { kem, pk, sk, ct, ss, m }
}

/// 1. Referenz: ehrliche Kapselung/Entkapselung stimmt überein.
#[test]
fn ind01_roundtrip() {
    let a = aufbau(0x1);
    assert_eq!(a.kem.decaps(&a.sk, &a.ct), a.ss);
    // Zweite Kapselung mit derselben Nachricht muss denselben Chiffretext geben
    // (deterministisch, weil die Münzen aus m und h(pk) abgeleitet werden).
    let (ct2, ss2) = a.kem.encaps_derand(&a.pk, &a.m);
    assert_eq!(ct2, a.ct);
    assert_eq!(ss2, a.ss);
}

/// 2. Jeder einzelne Bitfehler an einer Stichprobe von Positionen läuft in die
///    Ablehnung: kein Absturz, anderes Secret, und reproduzierbar.
#[test]
fn ind02_bitfehler_werden_abgelehnt() {
    let a = aufbau(0x2);
    let mut rng = Rng::new(0x2);
    let mut geprueft = 0usize;
    for _ in 0..200 {
        let pos = rng.below(CT_LEN);
        let bit = rng.below(8);
        let mut ct = a.ct;
        ct[pos] ^= 1 << bit;

        let ss1 = catch_unwind(AssertUnwindSafe(|| a.kem.decaps(&a.sk, &ct)))
            .expect("Absturz bei manipuliertem Chiffretext");
        let ss2 = catch_unwind(AssertUnwindSafe(|| a.kem.decaps(&a.sk, &ct)))
            .expect("Absturz im zweiten Lauf");
        assert_eq!(ss1, ss2, "Ablehnungs-Secret ist nicht deterministisch");
        assert_ne!(ss1, a.ss, "Manipulierter Chiffretext liefert das ehrliche Secret");
        assert_eq!(ss1.len(), SS_LEN);
        geprueft += 1;
    }
    assert_eq!(geprueft, 200);
}

/// 3. Ein Fehler im v-Teil (dort sitzt die Nachricht) muss ebenfalls in die
///    Ablehnung laufen — nicht in ein "Ersatz-Secret" aus Teilinformation.
#[test]
fn ind03_manipulierte_nachricht_im_ct() {
    let a = aufbau(0x3);
    let mut gesehen = std::collections::HashSet::new();
    for pos in (CT_LEN / 2)..CT_LEN {
        let mut ct = a.ct;
        ct[pos] ^= 0x80;
        let ss = a.kem.decaps(&a.sk, &ct);
        assert_ne!(ss, a.ss, "v-Manipulation bei Position {pos} nicht abgelehnt");
        gesehen.insert(ss);
    }
    // Alle diese Ablehnungen hängen am Hash des jeweiligen Chiffretexts,
    // sie müssen also verschieden sein (keine Konstante, keine Teilinfo).
    assert!(
        gesehen.len() > CT_LEN / 4,
        "Ablehnungs-Secrets sind zu ähnlich: nur {} verschieden",
        gesehen.len()
    );
}

/// 4. Koeffizienten oberhalb von q (ungültige Polynom-Schranken).
///
/// Nach dem Fix in `decode_poly`/`FieldElement::from_plain` ist das ein
/// normaler Ablehnungsfall: der Rohwert wird zweigfrei nach [0, q) reduziert,
/// **in Debug- und Release-Build gleich**. Eine Panik ist ein Fehler.
#[test]
fn ind04_koeffizienten_ueber_q() {
    let a = aufbau(0x4);
    let mut ct = a.ct;
    for pos in 0..CT_LEN {
        ct[pos] = 0xFF; // jeder Koeffizient = 65535 >= q
    }
    let ss = catch_unwind(AssertUnwindSafe(|| a.kem.decaps(&a.sk, &ct)))
        .unwrap_or_else(|_| {
            panic!(
                "Absturz auf ct mit Koeffizienten >= q ({})",
                if cfg!(debug_assertions) { "Debug" } else { "Release" }
            )
        });
    assert_ne!(ss, a.ss, "ct mit Koeffizienten >= q wurde akzeptiert");
    let nochmal = a.kem.decaps(&a.sk, &ct);
    assert_eq!(ss, nochmal, "nicht deterministisch");
    eprintln!("ind04: Koeffizienten >= q werden kanonisch reduziert, kein Panikpfad");
}

/// 5. Zufällige Chiffretexte (nicht von uns erzeugt) dürfen nie abstürzen.
#[test]
fn ind05_zufalls_chiffretexte() {
    let a = aufbau(0x5);
    let mut rng = Rng::new(0x5);
    for runde in 0..64 {
        let mut ct = [0u8; CT_LEN];
        rng.fill(&mut ct);
        let ergebnis = catch_unwind(AssertUnwindSafe(|| a.kem.decaps(&a.sk, &ct)));
        match ergebnis {
            Ok(ss) => {
                let nochmal = a.kem.decaps(&a.sk, &ct);
                assert_eq!(ss, nochmal, "Runde {runde}: nicht deterministisch");
                // Der ehrliche Chiffretext hat eine andere Länge als der Zufall —
                // Gleichheit wäre ein Indiz für ein Leck, kein Beweis.
                assert_ne!(ss, a.ss, "Runde {runde}: Zufalls-Chiffretext akzeptiert");
            }
            Err(_) => panic!(
                "Runde {runde}: Absturz auf Zufalls-Chiffretext ({})",
                if cfg!(debug_assertions) { "Debug" } else { "Release" }
            ),
        }
    }
}

/// 6. Manipulierter sk darf die Ablehnung nicht aushebeln.
#[test]
fn ind06_manipulierter_sk() {
    let a = aufbau(0x6);
    let mut rng = Rng::new(0x6);
    for _ in 0..32 {
        let mut sk = a.sk;
        let pos = rng.below(SK_LEN);
        sk[pos] ^= 1 << rng.below(8);
        let ss = catch_unwind(AssertUnwindSafe(|| a.kem.decaps(&sk, &a.ct)))
            .expect("Absturz bei manipuliertem sk");
        assert_ne!(ss, a.ss, "Manipulierter sk liefert trotzdem das ehrliche Secret");
    }
}

/// 7. Kein `Result`-Rückgabewert, kein Panik-Kanal: die Signatur ist
///    feste Länge, und der Fehlerfall ist von außen nicht unterscheidbar.
#[test]
fn ind07_signatur_und_kanallaenge() {
    let a = aufbau(0x7);
    let mut ct = a.ct;
    ct[0] ^= 1;
    let ss: [u8; SS_LEN] = a.kem.decaps(&a.sk, &ct);
    assert_eq!(ss.len(), SS_LEN);
    // Zwei verschiedene Ablehnungen gleicher Länge — kein Längen-Orakel.
    let mut ct2 = a.ct;
    ct2[1] ^= 1;
    let ss2: [u8; SS_LEN] = a.kem.decaps(&a.sk, &ct2);
    assert_eq!(ss.len(), ss2.len());
}
