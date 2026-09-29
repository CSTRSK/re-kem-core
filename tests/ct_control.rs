//! Positivkontrolle für den Valgrind-Audit.
//!
//! Ohne diese Kontrolle wäre ein grüner ct-grind-Lauf wertlos: er könnte
//! genauso gut bedeuten, dass die Vergiftung oder die Erkennung nicht wirkt.
//! Hier wird absichtlich auf vergifteten Daten verzweigt und damit indiziert.
//!
//! Erwartung: Valgrind MELDET Fehler (Exitcode != 0 mit --error-exitcode).
//! Der Runner `scripts/run_harnesses.sh` dreht das Ergebnis entsprechend um.
mod common;

use common::vg::{self, Rng};
use std::hint::black_box;

#[inline(never)]
fn arm_a() -> usize {
    1
}

#[inline(never)]
fn arm_b() -> usize {
    2
}

/// Verzweigt auf einem Geheimnis — das klassische Leck.
#[test]
fn kontrolle_01_sprung_auf_geheimnis() {
    let mut geheim = [0u8; 8];
    Rng::new(0x1234_5678).fill(&mut geheim);
    vg::make_mem_undefined(&mut geheim);

    // absichtlich datenabhängig. black_box verhindert, dass LLVM den Zweig
    // zu einem cmov macht - sonst wäre die Kontrolle wirkungslos, weil der
    // Compiler die Verzweigung selbst schon entfernt hätte.
    // Zwei nicht-inlined Aufrufe: die kann LLVM nicht speculativ berechnen,
    // es muss also wirklich verzweigt werden (cmov reicht hier nicht).
    let g = black_box(geheim[0]);
    let zweig = if g > 128 { arm_a() } else { arm_b() };
    black_box(zweig);
}

/// Indiziert mit einem Geheimnis — die zweite Leckform (Cache/Adresse).
#[test]
fn kontrolle_02_index_auf_geheimnis() {
    let tabelle = [11u32, 22, 33, 44, 55, 66, 77, 88];
    let mut geheim = [0u8; 1];
    Rng::new(0x8765_4321).fill(&mut geheim);
    vg::make_mem_undefined(&mut geheim);

    let g = black_box(geheim[0]) as usize;
    let idx = g % tabelle.len();
    black_box(tabelle[idx]);
}

/// Multiplikation mit geheimem Faktor, Ergebnis wieder als Index —
/// dieselbe Bauform, in der ein Compiler aus einer "sicheren" Maske einen
/// Sprung machen würde.
#[test]
fn kontrolle_03_produkt_als_index() {
    let mut geheim = [0u8; 2];
    Rng::new(0xDEAD_BEEF).fill(&mut geheim);
    vg::make_mem_undefined(&mut geheim);

    let puffer = *black_box(&[7u8, 9, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61]);
    let a = black_box(geheim[0]) as usize;
    let b = black_box(geheim[1]) as usize;
    let idx = (a.wrapping_mul(b)) & 15;
    black_box(puffer[idx]);
}
