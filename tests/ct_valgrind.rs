//! Constant-Time-Audit mit Valgrind (ct-grind).
//!
//! Idee: Geheimnisse werden als "unbekannt" markiert. Memcheck meldet dann
//! jeden bedingten Sprung und jede Speicheradresse, die von diesen Werten
//! abhängt — die zwei Formen von Leck, die ein Compiler erzeugen kann.
//!
//! Zwei Regeln, an die sich dieser Test halten muss, sonst misst er sich selbst:
//!
//! 1. **Nur echte Geheimnisse vergiften.** `seed_a` erzeugt die *öffentliche*
//!    Matrix A; die Verwerfungsschleife in `expand_a` darf — und soll — von
//!    diesen Bytes abhängen. Wird der Seed vergiftet, meldet der Audit einen
//!    Sprung auf öffentlichen Daten (Fehlalarm erster Güte).
//! 2. **Nie auf vergifteten Werten verzweigen.** Ausgaben werden mit
//!    `black_box` verbraucht und vor jedem Vergleich erst wieder als bekannt
//!    markiert — sonst meldet Valgrind den Testcode.
//!
//! Erwartung: 0 Fehler unter `valgrind --error-exitcode=99`.
mod common;

use common::vg::{self, Rng};
use re_kem_core::ntt::{NttContext, Poly};
use re_kem_core::N;
use re_kem_core::{FieldElement, ReKem, CT_LEN, PK_LEN, SEED_LEN, SK_LEN};
use std::hint::black_box;

/// Saatwerte: `seed_a` bleibt öffentlich, `noise` und `z` sind geheim.
fn aufbau(seed: u64) -> ([u8; SEED_LEN], [u8; SEED_LEN], [u8; SEED_LEN], [u8; SEED_LEN]) {
    let mut rng = Rng::new(seed);
    let mut a = [0u8; SEED_LEN];
    let mut n = [0u8; SEED_LEN];
    let mut z = [0u8; SEED_LEN];
    let mut m = [0u8; SEED_LEN];
    rng.fill(&mut a);
    rng.fill(&mut n);
    rng.fill(&mut z);
    rng.fill(&mut m);
    (a, n, z, m)
}

/// 1. Schlüsselerzeugung, Kapselung, Entkapselung — vergiftet werden die
///    Rauschsaat, der Zweitschlüssel z und die Nachricht.
#[test]
fn ct01_keygen_encaps_decaps() {
    let kem = ReKem::new();
    let (seed_a, mut noise, mut z, mut m) = aufbau(0x2026_0928_C0FF_EE01);

    vg::make_mem_undefined(&mut noise);
    vg::make_mem_undefined(&mut z);

    let (pk, sk) = kem.keygen_derand(&seed_a, &noise, &z);

    vg::make_mem_undefined(&mut m);
    let (ct, mut ss_sender) = kem.encaps_derand(&pk, &m);
    let mut ss_receiver = kem.decaps(&sk, &ct);

    black_box((&pk, &ct));

    vg::make_mem_defined(&mut ss_sender);
    vg::make_mem_defined(&mut ss_receiver);
    assert_eq!(ss_sender, ss_receiver, "Kapselung/Entkapselung inkonsistent");
    assert_eq!(sk.len(), SK_LEN);
    assert_eq!(ct.len(), CT_LEN);
    assert_eq!(pk.len(), PK_LEN);
}

/// 2. Vorwärts-NTT, punktweise Multiplikation und Invers-NTT über vergiftete
///    Koeffizienten — der Kern der Rechnung.
#[test]
fn ct02_ntt_vorwaerts_und_invers() {
    let ctx = NttContext::<N>::new();
    let mut rng = Rng::new(0x2026_0928_C0FF_EE02);

    let mut a = Poly::<N>::zero();
    let mut b = Poly::<N>::zero();
    for i in 0..N {
        a.coeffs[i] = FieldElement::from_plain((rng.next_u64() % re_kem_core::Q as u64) as u16);
        b.coeffs[i] = FieldElement::from_plain((rng.next_u64() % re_kem_core::Q as u64) as u16);
    }
    vg::make_mem_undefined(&mut a.coeffs);
    vg::make_mem_undefined(&mut b.coeffs);

    let mut produkt = ctx.mul(&a, &b);
    let mut summe = a.add(&b);
    let mut differenz = a.sub(&b);
    let mut skaliert = a.scale(FieldElement::one());

    black_box((&produkt, &summe, &differenz, &skaliert));

    // Erst jetzt bekannt machen — auch die Eingaben, sonst verzweigt der
    // Vergleich unten wieder auf vergifteten Werten.
    vg::make_mem_defined(&mut a.coeffs);
    vg::make_mem_defined(&mut b.coeffs);
    vg::make_mem_defined(&mut produkt.coeffs);
    vg::make_mem_defined(&mut summe.coeffs);
    vg::make_mem_defined(&mut differenz.coeffs);
    vg::make_mem_defined(&mut skaliert.coeffs);
    assert_eq!(summe.add(&differenz), a.add(&a), "a+b + (a-b) == 2a verletzt");
}

/// 3. Montgomery-Multiplikation, -Addition und -Subtraktion mit vergifteten
///    Eingaben.
#[test]
fn ct03_montgomery_multiplikation() {
    let mut rng = Rng::new(0x2026_0928_C0FF_EE03);
    let mut a: u16 = (rng.next_u64() % re_kem_core::Q as u64) as u16;
    let mut b: u16 = (rng.next_u64() % re_kem_core::Q as u64) as u16;
    vg::make_mem_undefined(std::slice::from_mut(&mut a));
    vg::make_mem_undefined(std::slice::from_mut(&mut b));

    let fa = FieldElement::from_plain(a);
    let fb = FieldElement::from_plain(b);
    let mut prod = fa.mul(fb).to_plain();
    let mut sum = fa.add(fb).to_plain();
    let mut diff = fa.sub(fb).to_plain();

    black_box((&prod, &sum, &diff));
    vg::make_mem_defined(std::slice::from_mut(&mut prod));
    vg::make_mem_defined(std::slice::from_mut(&mut sum));
    vg::make_mem_defined(std::slice::from_mut(&mut diff));
}

/// 4. Entkapselung mit vergiftetem **geheimen Teil** des Schlüssels.
///
/// Bewusst nicht der ganze sk: darin steckt auch pk (öffentlich). Vergiftet
/// werden nur die Koeffizienten von s und der Zweitschlüssel z.
#[test]
fn ct04_decaps_mit_vergiftetem_sk() {
    let kem = ReKem::new();
    let (seed_a, noise, z, m) = aufbau(0x2026_0928_C0FF_EE04);
    let (pk, mut sk) = kem.keygen_derand(&seed_a, &noise, &z);
    let (ct, mut ss_ok) = kem.encaps_derand(&pk, &m);

    let s_ende = re_kem_core::kem::POLY_LEN;
    let z_start = s_ende + PK_LEN + 32;
    vg::make_mem_undefined(&mut sk[..s_ende]); // s (geheim)
    vg::make_mem_undefined(&mut sk[z_start..]); // z (geheim)

    let mut ss = kem.decaps(&sk, &ct);

    black_box(&ss);
    vg::make_mem_defined(&mut ss);
    vg::make_mem_defined(&mut ss_ok);
    assert_eq!(ss, ss_ok, "Entkapselung mit vergiftetem sk weicht ab");
}

/// 5. Ablehnungspfad: der Chiffretext ist öffentlich, das Ergebnis nicht.
///    Hier läuft der Vergleich ct gegen ct' — die Stelle, an der ein
///    datenabhängiger Sprung am teuersten wäre.
#[test]
fn ct05_ablehnungspfad() {
    let kem = ReKem::new();
    let (seed_a, mut noise, z, m) = aufbau(0x2026_0928_C0FF_EE05);
    vg::make_mem_undefined(&mut noise);
    let (pk, sk) = kem.keygen_derand(&seed_a, &noise, &z);
    let (mut ct, _ss) = kem.encaps_derand(&pk, &m);
    ct[7] ^= 0x10; // Ablehnung erzwingen

    let mut ss_fail = kem.decaps(&sk, &ct);
    black_box(&ss_fail);
    vg::make_mem_defined(&mut ss_fail);
    let mut nochmal = kem.decaps(&sk, &ct);
    vg::make_mem_defined(&mut nochmal);
    assert_eq!(ss_fail, nochmal, "Ablehnung nicht deterministisch");
}

/// 6. Umgebung: läuft der Test überhaupt unter Valgrind? Ohne Valgrind sind
///    die Client-Requests folgenlose No-ops — der Lauf ist dann nur ein
///    Rauchtest. Der Runner macht den Unterschied sichtbar.
#[test]
fn ct06_umgebung() {
    let aktiv = vg::running_on_valgrind();
    eprintln!("valgrind aktiv: {aktiv}");
    assert!(!aktiv || vg::count_errors() == 0, "Valgrind meldet Fehler");
}
