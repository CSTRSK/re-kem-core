#![no_main]
//! Differential-Fuzzing: die NTT-Multiplikation gegen die naive Faltung.
//!
//! Geprüft wird `iNTT(NTT(a) ⊙ NTT(b)) == a·b mod (X^n + 1, q)` über alle
//! 512 Koeffizienten. Der Eingabestrom wird so gelesen, dass der Mutator
//! bevorzugt Randwerte trifft — 0, 1, q−1 und die Mitte (q−1)/2 —, weil dort
//! die Fehler sitzen und nicht in zufälligen Innenwerten.
use libfuzzer_sys::fuzz_target;
use re_kem_core::ntt::{NttContext, Poly};
use re_kem_core::{FieldElement, N, Q};

/// Zieht einen Koeffizienten: die niedrigen drei Bits des Steuerbytes wählen
/// einen Sonderwert, sonst einen breiten gestreuten Wert.
fn koeffizient(steuer: u8, roh: u16) -> u16 {
    match steuer & 0x7 {
        0 => 0,
        1 => 1,
        2 => Q as u16 - 1,
        3 => ((Q - 1) / 2) as u16, // Mitte des zulässigen Bereichs
        4 => (roh % Q as u16) as u16,
        5 => (roh % 3) as u16,
        6 => (Q as u16).wrapping_sub(1 + (roh % 4) as u16), // q-1 .. q-4, nie q selbst
        _ => ((roh as u32 * 257) % Q) as u16,
    }
}

/// Naive Schulbuch-Multiplikation in Z_q[X]/(X^n + 1).
fn naive_negazyklisch(a: &[u16; N], b: &[u16; N]) -> [u16; N] {
    let mut out = [0u32; N];
    for i in 0..N {
        for j in 0..N {
            let prod = (a[i] as u32) * (b[j] as u32);
            let k = i + j;
            if k < N {
                out[k] = (out[k] + prod) % Q;
            } else {
                // X^(i+j) = -X^(i+j-n)  (mod X^n + 1)
                let idx = k - N;
                out[idx] = (out[idx] + Q - (prod % Q)) % Q;
            }
        }
    }
    let mut res = [0u16; N];
    for i in 0..N {
        res[i] = out[i] as u16;
    }
    res
}

fuzz_target!(|daten: &[u8]| {
    // Streng groesser: die Steuerbytes liegen hinter den Koeffizienten, bei
    // genau 4*N Bytes waere der Rest leer (und der Modulo unten eine Division
    // durch null - genau das hat der erste Fuzzing-Lauf gefunden).
    if daten.len() <= 4 * N {
        return;
    }
    let rest = daten.len() - 4 * N;
    let mut a_roh = [0u16; N];
    let mut b_roh = [0u16; N];
    let mut a_koeff = [0u16; N];
    let mut b_koeff = [0u16; N];

    for i in 0..N {
        a_roh[i] = u16::from_le_bytes([daten[2 * i], daten[2 * i + 1]]);
        b_roh[i] = u16::from_le_bytes([daten[2 * N + 2 * i], daten[2 * N + 2 * i + 1]]);
        a_koeff[i] = koeffizient(daten[4 * N + i % rest], a_roh[i]);
        b_koeff[i] = koeffizient(daten[4 * N + (i + 1) % rest], b_roh[i]);
    }

    let mut a = Poly::<N>::zero();
    let mut b = Poly::<N>::zero();
    for i in 0..N {
        a.coeffs[i] = FieldElement::from_plain(a_koeff[i]);
        b.coeffs[i] = FieldElement::from_plain(b_koeff[i]);
    }

    let ctx = NttContext::<N>::new();
    let mut res = ctx.mul(&a, &b);
    let erwartet = naive_negazyklisch(&a_koeff, &b_koeff);

    for i in 0..N {
        let got = res.coeffs[i].to_plain();
        assert!(
            (got as u32) < Q,
            "Koeffizient {i} liegt ausserhalb von [0, q): {got}"
        );
        assert_eq!(
            got, erwartet[i],
            "NTT-Multiplikation weicht bei Koeffizient {i} von der naiven Faltung ab"
        );
    }
    // Ergebnis ausdruecklich "benutzen", damit die Schleife nicht wegoptimiert wird.
    core::hint::black_box(&mut res);
});
