//! Ungeprüfte Bytes auf dem Draht: `decode_poly` darf nie paniken.
//!
//! Der Test läuft **absichtlich auch in Debug-Builds** (`cargo test`, ohne
//! `--release`): genau dort schlug früher das `debug_assert!` in
//! `FieldElement::from_plain` zu, wenn ein Chiffretext-Koeffizient ≥ q war.
//! Nach dem Fix ist die Funktion total — für jeden der 65.536 möglichen
//! 16-Bit-Werte —, und Debug und Release rechnen dasselbe.
mod common;

use common::vg::Rng;
use re_kem_core::sampling::{decode_poly, encode_poly};
use re_kem_core::{FieldElement, Poly, Q, N};
use std::panic::{catch_unwind, AssertUnwindSafe};

/// Puffer mit einem festen Rohwert im ersten Koeffizienten.
fn puffer_mit(roh: u16) -> [u8; 2 * N] {
    let mut buf = [0u8; 2 * N];
    buf[0] = (roh & 0xFF) as u8;
    buf[1] = (roh >> 8) as u8;
    buf
}

/// 1. Erschöpfend: alle 65.536 Rohwerte werden auf `v mod q` abgebildet,
///    ohne Panik, unabhängig vom Build-Profil.
#[test]
fn dec01_alle_16bit_werte() {
    let erwartet: Vec<u16> = (0..=u16::MAX).map(|v| (v % Q as u16) as u16).collect();

    for roh in 0..=u16::MAX {
        let buf = puffer_mit(roh);
        let poly = catch_unwind(AssertUnwindSafe(|| decode_poly::<N>(&buf)))
            .unwrap_or_else(|_| panic!("decode_poly panikt bei Rohwert {roh}"));
        let got = poly.coeffs[0].to_plain();
        assert_eq!(
            got,
            erwartet[roh as usize],
            "Rohwert {roh}: erwartet {} (mod q), bekommen {got}",
            erwartet[roh as usize]
        );
    }
    eprintln!("dec01: 65536 Rohwerte geprüft, kein Panikpfad");
}

/// 2. Der frühere Absturzfall: ein Chiffretext aus lauter 0xFF.
#[test]
fn dec02_lauter_0xff() {
    let buf = [0xFFu8; 2 * N];
    let poly = catch_unwind(AssertUnwindSafe(|| decode_poly::<N>(&buf)))
        .expect("decode_poly panikt auf einem Chiffretext aus 0xFF-Bytes");
    // 0xFFFF mod q == 4095
    assert_eq!(poly.coeffs[0].to_plain(), (0xFFFFu32 % Q) as u16);
}

/// 3. Zufällige Puffer: nie Panik, immer im kanonischen Bereich.
#[test]
fn dec03_zufallspuffer() {
    let mut rng = Rng::new(0xDEC0_DE00);
    for _ in 0..200 {
        let mut buf = [0u8; 2 * N];
        rng.fill(&mut buf);
        let poly = catch_unwind(AssertUnwindSafe(|| decode_poly::<N>(&buf)))
            .expect("decode_poly panikt auf Zufallsbytes");
        for (i, c) in poly.coeffs.iter().enumerate() {
            assert!((c.to_plain() as u32) < Q, "Koeffizient {i} >= q");
        }
    }
}

/// 4. Der Rückweg bleibt unberührt: legitime Koeffizienten überstehen
///    Kodierung und Dekodierung unverändert.
#[test]
fn dec04_rundreise_mit_gueltigen_werten() {
    let mut p = Poly::zero();
    let mut rng = Rng::new(0x5EED);
    let mut werte = Vec::new();
    for i in 0..N {
        let v = (rng.next_u64() % Q as u64) as u16;
        werte.push(v);
        p.coeffs[i] = FieldElement::from_plain(v);
    }
        let mut kodiert = [0u8; 2 * N];
    encode_poly::<N>(&p, &mut kodiert);
    let zurueck = decode_poly::<N>(&kodiert);
    for i in 0..N {
        assert_eq!(zurueck.coeffs[i].to_plain(), werte[i], "Koeffizient {i}");
    }
}

/// 5. `from_plain` selbst ist total: auch der direkte Aufruf mit Werten ≥ q
///    darf nicht paniken (Debug-Build!) und muss modulo q landen.
#[test]
fn dec05_from_plain_ist_total() {
    for roh in [0u16, 1, Q as u16 - 1, Q as u16, Q as u16 + 1, 2 * Q as u16, u16::MAX] {
        let fe = catch_unwind(AssertUnwindSafe(|| FieldElement::from_plain(roh)))
            .unwrap_or_else(|_| panic!("from_plain panikt bei {roh}"));
        assert_eq!(
            fe.to_plain(),
            (roh as u32 % Q) as u16,
            "from_plain({roh}) ist nicht v mod q"
        );
    }
}
