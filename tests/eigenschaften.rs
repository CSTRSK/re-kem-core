//! Eigenschafts- und Spezifikationstests.
//!
//! Die vorhandenen Harnesses prüfen Härtung (Constant-Time, Fuzzing, IND-CCA2,
//! Fault-Injection) und die Unit-Tests prüfen Einzelfälle. Diese Datei schließt
//! die Lücke dazwischen:
//!
//! * A. Ringaxiome der NTT-Multiplikation (Kommutativität, Assoziativität,
//!   Distributivität, Einselement, X^n = -1) — in n = 512 **und** n = 1024.
//! * B. Körperarithmetik erschöpfend über alle Reste.
//! * C. Sampling: unabhängig aus der Spezifikation nachgerechnet, plus
//!   Statistik (Mittelwert, Varianz, Gleichverteilung).
//! * D. KEM gegen die dokumentierte Spezifikation (H, G, KDF) **ohne** den
//!   Glue-Code aus `kem.rs` — Schlüssel- und Chiffretext-Layout, Ablehnungs-
//!   Secret, Sensitivität auf jedes Eingabebit.
//! * E. Totalität: keine Eingabe darf paniken (Debug **und** Release).
//! * F. Trait-/Registry-Schicht: Längenfehler, Kreuzbenutzung der Parametersätze.
//!
//! Ausführen:
//!   cargo test --test eigenschaften            # Debug (so wie der Fuzzer baut)
//!   cargo test --release --test eigenschaften  # Release
mod common;

use common::vg::Rng;
use re_kem_core::api::{KemError, Registry};
use re_kem_core::ntt::NttContext;
use re_kem_core::sampling::{cbd_sample, decode_poly, encode_poly, expand_a, ETA};
use re_kem_core::version::Algorithm;
use re_kem_core::{
    FieldElement, KemGeneric, Poly, ReKem, ReKem1024, CT_LEN, CT_LEN_1024, PK_LEN, PK_LEN_1024,
    Q, SEED_LEN, SK_LEN, SK_LEN_1024, SS_LEN,
};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Sha3_256, Sha3_512, Shake256};

/// Im Debug-Profil (langsam) weniger Wiederholungen als im Release-Profil.
fn skaliert(release: usize, debug: usize) -> usize {
    if cfg!(debug_assertions) {
        debug
    } else {
        release
    }
}

// ───────────────────────────── Hilfsfunktionen ─────────────────────────────

fn poly_aus<const N: usize>(mut f: impl FnMut(usize) -> u16) -> Poly<N> {
    let mut p = Poly::<N>::zero();
    for i in 0..N {
        p.coeffs[i] = FieldElement::from_plain(f(i));
    }
    p
}

fn zufalls_poly<const N: usize>(rng: &mut Rng) -> Poly<N> {
    poly_aus::<N>(|_| (rng.next_u64() % Q as u64) as u16)
}

fn klartext<const N: usize>(p: &Poly<N>) -> Vec<u16> {
    (0..N).map(|i| p.coeffs[i].to_plain()).collect()
}

fn monom<const N: usize>(i: usize) -> Poly<N> {
    poly_aus::<N>(|k| if k == i { 1 } else { 0 })
}

fn sha3_256(teile: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    for t in teile {
        Digest::update(&mut h, t);
    }
    h.finalize().into()
}

fn sha3_512(teile: &[&[u8]]) -> [u8; 64] {
    let mut h = Sha3_512::new();
    for t in teile {
        Digest::update(&mut h, t);
    }
    h.finalize().into()
}

fn shake256(teile: &[&[u8]], laenge: usize) -> Vec<u8> {
    let mut x = Shake256::default();
    for t in teile {
        Update::update(&mut x, t);
    }
    let mut leser = x.finalize_xof();
    let mut out = vec![0u8; laenge];
    leser.read(&mut out);
    out
}

fn zufall32(rng: &mut Rng) -> [u8; 32] {
    let mut b = [0u8; 32];
    rng.fill(&mut b);
    b
}

fn bit_msb(daten: &[u8], idx: usize) -> u32 {
    ((daten[idx / 8] >> (7 - (idx % 8))) & 1) as u32
}

fn kippe_bit(daten: &mut [u8], pos: usize) {
    daten[pos / 8] ^= 1 << (pos % 8);
}

// ═════════════════════════ A. Ringaxiome der NTT ═════════════════════════

fn ring_axiome<const N: usize>(runden: usize) {
    let ctx = NttContext::<N>::new();
    let mut rng = Rng::new(0xA11CE + N as u64);
    let eins = monom::<N>(0);
    let null = Poly::<N>::zero();

    for _ in 0..runden {
        let a = zufalls_poly::<N>(&mut rng);
        let b = zufalls_poly::<N>(&mut rng);
        let c = zufalls_poly::<N>(&mut rng);

        // Kommutativität
        assert_eq!(ctx.mul(&a, &b), ctx.mul(&b, &a), "n={N}: a*b != b*a");
        // Assoziativität
        assert_eq!(
            ctx.mul(&ctx.mul(&a, &b), &c),
            ctx.mul(&a, &ctx.mul(&b, &c)),
            "n={N}: (a*b)*c != a*(b*c)"
        );
        // Distributivität
        assert_eq!(
            ctx.mul(&a, &b.add(&c)),
            ctx.mul(&a, &b).add(&ctx.mul(&a, &c)),
            "n={N}: a*(b+c) != a*b + a*c"
        );
        // Einselement und Nullelement
        assert_eq!(ctx.mul(&a, &eins), a, "n={N}: a*1 != a");
        assert_eq!(ctx.mul(&a, &null), null, "n={N}: a*0 != 0");
        // Additive Gruppe: (a + b) - b == a
        assert_eq!(a.add(&b).sub(&b), a, "n={N}: (a+b)-b != a");
        // Skalarverträglichkeit: (k·a)*b == k·(a*b)
        let k = FieldElement::from_plain((rng.next_u64() % Q as u64) as u16);
        assert_eq!(
            ctx.mul(&a.scale(k), &b),
            ctx.mul(&a, &b).scale(k),
            "n={N}: (k*a)*b != k*(a*b)"
        );
    }
}

#[test]
fn eig01_ringaxiome_n512() {
    ring_axiome::<512>(skaliert(40, 6));
}

#[test]
fn eig02_ringaxiome_n1024() {
    ring_axiome::<1024>(skaliert(20, 3));
}

/// X^i · X^j = X^(i+j), und bei i+j >= n gilt X^n = -1 (negazyklisch).
fn monom_produkte<const N: usize>(paare: usize) {
    let ctx = NttContext::<N>::new();
    let mut rng = Rng::new(0xB0B + N as u64);

    // Randfälle ausdrücklich: Überlauf genau an der Kante.
    let mut ij: Vec<(usize, usize)> = vec![(0, 0), (1, N - 1), (N - 1, N - 1), (N / 2, N / 2)];
    for _ in 0..paare {
        ij.push((rng.below(N), rng.below(N)));
    }

    for (i, j) in ij {
        let erg = klartext(&ctx.mul(&monom::<N>(i), &monom::<N>(j)));
        let mut erwartet = vec![0u16; N];
        if i + j < N {
            erwartet[i + j] = 1;
        } else {
            erwartet[i + j - N] = (Q - 1) as u16; // -1 mod q
        }
        assert_eq!(erg, erwartet, "n={N}: X^{i} * X^{j} falsch");
    }
}

#[test]
fn eig03_monomprodukte_und_x_hoch_n_ist_minus_eins() {
    monom_produkte::<512>(skaliert(300, 40));
    monom_produkte::<1024>(skaliert(100, 15));
}

// ═════════════════════════ B. Körperarithmetik ═══════════════════════════

#[test]
fn eig04_koerper_rundreise_alle_reste() {
    for a in 0..Q as u16 {
        assert_eq!(FieldElement::from_plain(a).to_plain(), a, "Rundreise {a}");
    }
    assert_eq!(FieldElement::zero().to_plain(), 0);
    assert_eq!(FieldElement::one().to_plain(), 1);
}

#[test]
fn eig05_koerper_operationen_gegen_naive_rechnung() {
    let q = Q as u64;
    let mut rng = Rng::new(0xF1E1D);
    let stuetz: Vec<u16> = {
        let mut v = vec![0u16, 1, 2, (Q - 1) as u16, (Q - 2) as u16, (Q / 2) as u16];
        for _ in 0..58 {
            v.push((rng.next_u64() % q) as u16);
        }
        v
    };

    // Ein Operand läuft über ALLE Reste, der andere über die Stützmenge.
    for a in 0..Q as u16 {
        let fa = FieldElement::from_plain(a);
        for &b in &stuetz {
            let fb = FieldElement::from_plain(b);
            let (a64, b64) = (a as u64, b as u64);
            assert_eq!(fa.mul(fb).to_plain() as u64, (a64 * b64) % q, "mul {a}*{b}");
            assert_eq!(fa.add(fb).to_plain() as u64, (a64 + b64) % q, "add {a}+{b}");
            assert_eq!(
                fa.sub(fb).to_plain() as u64,
                (a64 + q - b64) % q,
                "sub {a}-{b}"
            );
        }
        // Gruppen-/Ringeigenschaften je Element
        assert_eq!(fa.mul(FieldElement::one()), fa, "a*1 {a}");
        assert_eq!(fa.mul(FieldElement::zero()), FieldElement::zero(), "a*0 {a}");
        assert_eq!(fa.add(FieldElement::zero()), fa, "a+0 {a}");
        assert_eq!(fa.sub(fa), FieldElement::zero(), "a-a {a}");
    }
}

#[test]
fn eig06_koerper_distributivgesetz_und_inverse_stichprobe() {
    let q = Q as u64;
    let mut rng = Rng::new(0xD157);
    for _ in 0..20_000 {
        let a = FieldElement::from_plain((rng.next_u64() % q) as u16);
        let b = FieldElement::from_plain((rng.next_u64() % q) as u16);
        let c = FieldElement::from_plain((rng.next_u64() % q) as u16);
        assert_eq!(a.mul(b.add(c)), a.mul(b).add(a.mul(c)));
        assert_eq!(a.mul(b), b.mul(a));
        assert_eq!(a.add(b).sub(b), a);
    }
    // q ist prim: a^(q-1) == 1 für jedes a != 0 (Fermat), Potenz per Quadrieren.
    for _ in 0..200 {
        let a = FieldElement::from_plain((1 + rng.next_u64() % (q - 1)) as u16);
        let mut basis = a;
        let mut erg = FieldElement::one();
        let mut e = q - 1;
        while e > 0 {
            if e & 1 == 1 {
                erg = erg.mul(basis);
            }
            basis = basis.mul(basis);
            e >>= 1;
        }
        assert_eq!(erg, FieldElement::one(), "Fermat verletzt");
    }
}

// ═════════════════════════════ C. Sampling ═══════════════════════════════

/// CBD(η) unabhängig aus der dokumentierten Spezifikation:
/// SHAKE-256(seed ‖ nonce), 2η Bit je Koeffizient, MSB zuerst, a − b mod q.
fn cbd_referenz<const N: usize>(seed: &[u8], nonce: u8) -> Vec<u16> {
    let bits = 2 * ETA;
    let roh = shake256(&[seed, &[nonce]], (bits * N + 7) / 8);
    (0..N)
        .map(|i| {
            let basis = i * bits;
            let a: u32 = (0..ETA).map(|j| bit_msb(&roh, basis + j)).sum();
            let b: u32 = (0..ETA).map(|j| bit_msb(&roh, basis + ETA + j)).sum();
            ((a + Q - b) % Q) as u16
        })
        .collect()
}

/// a(x) per Rejection Sampling unabhängig aus der Spezifikation.
fn expand_a_referenz<const N: usize>(seed: &[u8]) -> Vec<u16> {
    let q = Q as usize;
    let grenze = (65536 / q) * q;
    let mut koeff: Vec<u16> = Vec::new();
    let mut nonce: u8 = 0;
    while koeff.len() < N {
        let fehlt = N - koeff.len();
        let roh = shake256(&[seed, &[nonce]], fehlt * 3);
        nonce = nonce.wrapping_add(1);
        let mut i = 0;
        while i + 1 < roh.len() && koeff.len() < N {
            let v = roh[i] as usize | ((roh[i + 1] as usize) << 8);
            if v < grenze {
                koeff.push((v % q) as u16);
            }
            i += 2;
        }
    }
    koeff
}

#[test]
fn eig07_cbd_stimmt_mit_unabhaengiger_referenz_ueberein() {
    let mut rng = Rng::new(0xCBD);
    for _ in 0..skaliert(60, 10) {
        let seed = zufall32(&mut rng);
        let nonce = (rng.next_u64() & 0xFF) as u8;
        assert_eq!(
            klartext(&cbd_sample::<512>(&seed, nonce)),
            cbd_referenz::<512>(&seed, nonce)
        );
        assert_eq!(
            klartext(&cbd_sample::<1024>(&seed, nonce)),
            cbd_referenz::<1024>(&seed, nonce)
        );
    }
}

#[test]
fn eig08_expand_a_stimmt_mit_unabhaengiger_referenz_ueberein() {
    let mut rng = Rng::new(0xE49A);
    for _ in 0..skaliert(60, 10) {
        let seed = zufall32(&mut rng);
        assert_eq!(
            klartext(&expand_a::<512>(&seed)),
            expand_a_referenz::<512>(&seed)
        );
        assert_eq!(
            klartext(&expand_a::<1024>(&seed)),
            expand_a_referenz::<1024>(&seed)
        );
    }
}

#[test]
fn eig09_cbd_statistik_mittelwert_varianz_wertebereich() {
    // CBD(8): a, b ~ Bin(8, 1/2)  =>  a − b hat Mittel 0 und Varianz 2·8/4 = 4.
    let mut rng = Rng::new(0x57A7);
    let seeds = skaliert(80, 20);
    let mut summe = 0f64;
    let mut quad = 0f64;
    let mut n_ges = 0f64;
    let mut vorkommen = [0usize; 2 * 8 + 1];

    for s in 0..seeds {
        let seed = zufall32(&mut rng);
        let p = cbd_sample::<512>(&seed, (s & 0xFF) as u8);
        for c in klartext(&p) {
            let c = c as i32;
            let zentriert = if c > (Q as i32) / 2 { c - Q as i32 } else { c };
            assert!(
                zentriert.abs() <= ETA as i32,
                "Koeffizient {zentriert} außerhalb [-{ETA}, {ETA}]"
            );
            vorkommen[(zentriert + ETA as i32) as usize] += 1;
            summe += zentriert as f64;
            quad += (zentriert * zentriert) as f64;
            n_ges += 1.0;
        }
    }
    let mittel = summe / n_ges;
    let varianz = quad / n_ges - mittel * mittel;
    assert!(mittel.abs() < 0.1, "Mittelwert {mittel} weicht von 0 ab");
    assert!(
        (3.8..=4.2).contains(&varianz),
        "Varianz {varianz} weicht von 4 ab"
    );
    // Die Werte -4..=4 müssen alle vorkommen (je ≥ 2,8 % Wahrscheinlichkeit).
    for k in -4i32..=4 {
        assert!(vorkommen[(k + ETA as i32) as usize] > 0, "Wert {k} fehlt");
    }
    // Symmetrie: P(+k) ≈ P(−k) für die häufigen Werte (±15 % Toleranz).
    for k in 1i32..=3 {
        let p = vorkommen[(k + ETA as i32) as usize] as f64;
        let m = vorkommen[(-k + ETA as i32) as usize] as f64;
        assert!((p - m).abs() / p.max(m) < 0.15, "Asymmetrie bei ±{k}");
    }
}

#[test]
fn eig10_expand_a_gleichverteilung() {
    let mut rng = Rng::new(0x6A1C);
    let seeds = skaliert(80, 20);
    let mut summe = 0f64;
    let mut n_ges = 0f64;
    let mut viertel = [0usize; 4];
    for _ in 0..seeds {
        let seed = zufall32(&mut rng);
        for c in klartext(&expand_a::<512>(&seed)) {
            assert!((c as u32) < Q, "Koeffizient {c} ≥ q");
            summe += c as f64;
            n_ges += 1.0;
            viertel[(c as usize * 4) / Q as usize] += 1;
        }
    }
    let mittel = summe / n_ges;
    // Gleichverteilung auf [0, q): Mittel (q−1)/2, Standardfehler ≈ q/√(12·n)
    let erwartet = (Q as f64 - 1.0) / 2.0;
    let sigma = Q as f64 / (12.0 * n_ges).sqrt();
    assert!(
        (mittel - erwartet).abs() < 6.0 * sigma,
        "Mittel {mittel} vs {erwartet} (σ={sigma})"
    );
    // Jedes Viertel ≈ 25 % (±3 Prozentpunkte).
    for (i, &v) in viertel.iter().enumerate() {
        let anteil = v as f64 / n_ges;
        assert!((anteil - 0.25).abs() < 0.03, "Viertel {i}: {anteil}");
    }
}

#[test]
fn eig11_sampling_reagiert_auf_jedes_seedbit_und_jede_nonce() {
    let seed = [0x5Au8; 32];
    let basis_cbd = klartext(&cbd_sample::<512>(&seed, 0));
    let basis_a = klartext(&expand_a::<512>(&seed));
    let mut gesehen_cbd = vec![basis_cbd.clone()];
    let mut gesehen_a = vec![basis_a.clone()];

    for bit in 0..256 {
        let mut s = seed;
        kippe_bit(&mut s, bit);
        let c = klartext(&cbd_sample::<512>(&s, 0));
        let a = klartext(&expand_a::<512>(&s));
        assert_ne!(c, basis_cbd, "cbd ignoriert Seedbit {bit}");
        assert_ne!(a, basis_a, "expand_a ignoriert Seedbit {bit}");
        assert!(!gesehen_cbd.contains(&c), "Kollision cbd bei Bit {bit}");
        assert!(!gesehen_a.contains(&a), "Kollision expand_a bei Bit {bit}");
        gesehen_cbd.push(c);
        gesehen_a.push(a);
    }

    // Alle 256 Nonces liefern paarweise verschiedene Rauschpolynome.
    let mut nonces: Vec<Vec<u16>> = Vec::new();
    for n in 0..=255u8 {
        let c = klartext(&cbd_sample::<512>(&seed, n));
        assert!(!nonces.contains(&c), "Nonce {n} kollidiert");
        nonces.push(c);
    }
}

#[test]
fn eig12_encode_layout_ist_little_endian_und_rundreise_ist_exakt() {
    let p = poly_aus::<512>(|i| match i {
        0 => 0x1234 % Q as u16,
        1 => 1,
        2 => (Q - 1) as u16,
        _ => (i as u16 * 37) % Q as u16,
    });
    let mut buf = vec![0u8; 1024];
    encode_poly::<512>(&p, &mut buf);
    let c0 = 0x1234u16 % Q as u16;
    assert_eq!(&buf[0..2], &c0.to_le_bytes());
    assert_eq!(&buf[2..4], &1u16.to_le_bytes());
    assert_eq!(&buf[4..6], &((Q - 1) as u16).to_le_bytes());
    assert_eq!(decode_poly::<512>(&buf), p);

    // Kanonische Bytes bleiben unter decode→encode unverändert (idempotent).
    let mut buf2 = vec![0u8; 1024];
    encode_poly::<512>(&decode_poly::<512>(&buf), &mut buf2);
    assert_eq!(buf, buf2);
}

// ═══════════════════ D. KEM gegen die Spezifikation ══════════════════════

type Kem512 = ReKem;
type Kem1024 = ReKem1024;

/// keygen_derand gegen die Spezifikation: pk = seed_a ‖ enc(a·s + e),
/// sk = enc(s) ‖ pk ‖ SHA3-256(pk) ‖ z.
fn keygen_spezifikation<const N: usize, const PK: usize, const SK: usize, const CT: usize>(
    kem: &KemGeneric<N, PK, SK, CT>,
    rng: &mut Rng,
) {
    let (sa, ns, z) = (zufall32(rng), zufall32(rng), zufall32(rng));
    let (pk, sk) = kem.keygen_derand(&sa, &ns, &z);
    let ctx = NttContext::<N>::new();

    let a = expand_a::<N>(&sa);
    let s = cbd_sample::<N>(&ns, 0);
    let e = cbd_sample::<N>(&ns, 1);
    let b = ctx.mul(&a, &s).add(&e);

    let mut pk_soll = vec![0u8; PK];
    pk_soll[..SEED_LEN].copy_from_slice(&sa);
    encode_poly::<N>(&b, &mut pk_soll[SEED_LEN..]);
    assert_eq!(&pk[..], &pk_soll[..], "n={N}: pk weicht von Spezifikation ab");

    let mut s_bytes = vec![0u8; 2 * N];
    encode_poly::<N>(&s, &mut s_bytes);
    assert_eq!(&sk[..2 * N], &s_bytes[..], "n={N}: sk.s");
    assert_eq!(&sk[2 * N..2 * N + PK], &pk[..], "n={N}: sk enthält pk");
    assert_eq!(
        &sk[2 * N + PK..2 * N + PK + 32],
        &sha3_256(&[&pk[..]])[..],
        "n={N}: sk.h(pk)"
    );
    assert_eq!(&sk[2 * N + PK + 32..], &z[..], "n={N}: sk.z");
}

#[test]
fn eig13_keygen_entspricht_der_spezifikation() {
    let mut rng = Rng::new(0x6E9);
    for _ in 0..skaliert(20, 4) {
        keygen_spezifikation(&Kem512::new(), &mut rng);
    }
    for _ in 0..skaliert(6, 2) {
        keygen_spezifikation(&Kem1024::new(), &mut rng);
    }
}

/// encaps_derand gegen die Spezifikation: Münzen und Schlüssel aus SHA3-512,
/// Chiffretext = enc(u) ‖ enc(v), Secret = SHAKE-256(k̄ ‖ SHA3-256(ct)).
fn encaps_spezifikation<const N: usize, const PK: usize, const SK: usize, const CT: usize>(
    kem: &KemGeneric<N, PK, SK, CT>,
    rng: &mut Rng,
) {
    let (sa, ns, z, m) = (zufall32(rng), zufall32(rng), zufall32(rng), zufall32(rng));
    let (pk, _sk) = kem.keygen_derand(&sa, &ns, &z);
    let (ct, ss) = kem.encaps_derand(&pk, &m);
    let ctx = NttContext::<N>::new();

    let hp = sha3_256(&[&pk[..]]);
    let g = sha3_512(&[&m[..], &hp[..]]);
    let (k_bar, muenzen) = (&g[..32], &g[32..]);

    let a = expand_a::<N>(&pk[..SEED_LEN]);
    let b = decode_poly::<N>(&pk[SEED_LEN..]);
    let r = cbd_sample::<N>(muenzen, 0);
    let e1 = cbd_sample::<N>(muenzen, 1);
    let e2 = cbd_sample::<N>(muenzen, 2);
    let nachricht = poly_aus::<N>(|i| {
        if i < SEED_LEN * 8 {
            ((Q / 2) as u16) * bit_msb(&m, i) as u16
        } else {
            0
        }
    });
    let u = ctx.mul(&a, &r).add(&e1);
    let v = ctx.mul(&b, &r).add(&e2).add(&nachricht);

    let mut ct_soll = vec![0u8; CT];
    encode_poly::<N>(&u, &mut ct_soll[..2 * N]);
    encode_poly::<N>(&v, &mut ct_soll[2 * N..]);
    assert_eq!(&ct[..], &ct_soll[..], "n={N}: ct weicht von Spezifikation ab");

    let hc = sha3_256(&[&ct[..]]);
    let ss_soll = shake256(&[k_bar, &hc[..]], SS_LEN);
    assert_eq!(&ss[..], &ss_soll[..], "n={N}: ss weicht von Spezifikation ab");
}

#[test]
fn eig14_encaps_entspricht_der_spezifikation() {
    let mut rng = Rng::new(0xE4C);
    for _ in 0..skaliert(20, 4) {
        encaps_spezifikation(&Kem512::new(), &mut rng);
    }
    for _ in 0..skaliert(6, 2) {
        encaps_spezifikation(&Kem1024::new(), &mut rng);
    }
}

/// Das Ablehnungs-Secret ist laut Spezifikation SHAKE-256(z ‖ SHA3-256(ct)) —
/// unabhängig von s, pk und der (unbrauchbaren) Nachricht.
fn ablehnung_spezifikation<const N: usize, const PK: usize, const SK: usize, const CT: usize>(
    kem: &KemGeneric<N, PK, SK, CT>,
    rng: &mut Rng,
    versuche: usize,
) {
    let (sa, ns, z, m) = (zufall32(rng), zufall32(rng), zufall32(rng), zufall32(rng));
    let (pk, sk) = kem.keygen_derand(&sa, &ns, &z);
    let (ct_ok, ss_ok) = kem.encaps_derand(&pk, &m);
    assert_eq!(kem.decaps(&sk, &ct_ok), ss_ok);

    for t in 0..versuche {
        let mut ct = ct_ok;
        // Verschiedene Manipulationsarten: ein Bit im u-Teil, im v-Teil, mehrere Bits.
        match t % 3 {
            0 => kippe_bit(&mut ct, rng.below(2 * N * 8)),
            1 => kippe_bit(&mut ct, 2 * N * 8 + rng.below(2 * N * 8)),
            _ => {
                for _ in 0..5 {
                    kippe_bit(&mut ct, rng.below(CT * 8));
                }
            }
        }
        if ct == ct_ok {
            continue; // Bits haben sich gegenseitig aufgehoben — kein Fall
        }
        let hc = sha3_256(&[&ct[..]]);
        let soll = shake256(&[&z[..], &hc[..]], SS_LEN);
        let ist = kem.decaps(&sk, &ct);
        assert_eq!(&ist[..], &soll[..], "n={N}: Ablehnungs-Secret falsch (Versuch {t})");
        assert_ne!(ist, ss_ok, "n={N}: echtes Secret nach Manipulation (Versuch {t})");

        // Unabhängigkeit von s und pk: anderes Schlüsselpaar, gleiches z, gleicher ct.
        let ns2 = zufall32(rng);
        let (_pk2, sk2) = kem.keygen_derand(&sa, &ns2, &z);
        assert_eq!(kem.decaps(&sk2, &ct), ist, "n={N}: Ablehnung hängt an s");
    }
}

#[test]
fn eig15_ablehnungs_secret_entspricht_der_spezifikation() {
    let mut rng = Rng::new(0xAB1E);
    ablehnung_spezifikation(&Kem512::new(), &mut rng, skaliert(60, 12));
    ablehnung_spezifikation(&Kem1024::new(), &mut rng, skaliert(12, 3));
}

#[test]
fn eig16_sensitivitaet_keygen_auf_jedes_seedbit() {
    let kem = Kem512::new();
    let mut rng = Rng::new(0x5E5);
    let (sa, ns, z) = (zufall32(&mut rng), zufall32(&mut rng), zufall32(&mut rng));
    let (pk0, sk0) = kem.keygen_derand(&sa, &ns, &z);
    assert_eq!(kem.keygen_derand(&sa, &ns, &z), (pk0, sk0), "nicht deterministisch");

    let schritt = skaliert(1, 8);
    for bit in (0..256).step_by(schritt) {
        // seed_a: ändert pk (Seed-Präfix UND b) und sk
        let mut sa2 = sa;
        kippe_bit(&mut sa2, bit);
        let (pk1, sk1) = kem.keygen_derand(&sa2, &ns, &z);
        assert_ne!(pk1, pk0, "seed_a-Bit {bit} ohne Wirkung auf pk");
        assert_ne!(&pk1[..SEED_LEN], &pk0[..SEED_LEN]);
        assert_ne!(sk1, sk0);

        // noise_seed: Präfix bleibt, b ändert sich
        let mut ns2 = ns;
        kippe_bit(&mut ns2, bit);
        let (pk2, sk2) = kem.keygen_derand(&sa, &ns2, &z);
        assert_eq!(&pk2[..SEED_LEN], &pk0[..SEED_LEN]);
        assert_ne!(&pk2[SEED_LEN..], &pk0[SEED_LEN..], "noise-Bit {bit} wirkungslos");
        assert_ne!(sk2, sk0);

        // z: pk identisch, sk unterscheidet sich NUR im letzten 32-Byte-Block
        let mut z2 = z;
        kippe_bit(&mut z2, bit);
        let (pk3, sk3) = kem.keygen_derand(&sa, &ns, &z2);
        assert_eq!(pk3, pk0, "z beeinflusst pk");
        assert_eq!(&sk3[..SK_LEN - 32], &sk0[..SK_LEN - 32], "z beeinflusst mehr als den Schluss");
        assert_ne!(&sk3[SK_LEN - 32..], &sk0[SK_LEN - 32..]);
    }
}

#[test]
fn eig17_sensitivitaet_encaps_auf_jedes_nachrichtenbit() {
    let kem = Kem512::new();
    let mut rng = Rng::new(0xDEAD);
    let (sa, ns, z, m) = (
        zufall32(&mut rng),
        zufall32(&mut rng),
        zufall32(&mut rng),
        zufall32(&mut rng),
    );
    let (pk, sk) = kem.keygen_derand(&sa, &ns, &z);
    let (ct0, ss0) = kem.encaps_derand(&pk, &m);

    let mut secrets = vec![ss0];
    let mut cts = vec![ct0];
    let schritt = skaliert(1, 4);
    for bit in (0..256).step_by(schritt) {
        let mut m2 = m;
        kippe_bit(&mut m2, bit);
        let (ct, ss) = kem.encaps_derand(&pk, &m2);
        assert!(!secrets.contains(&ss), "Secret-Kollision bei Nachrichtenbit {bit}");
        assert!(!cts.contains(&ct), "ct-Kollision bei Nachrichtenbit {bit}");
        assert_eq!(kem.decaps(&sk, &ct), ss, "Rundreise bei Nachrichtenbit {bit}");
        secrets.push(ss);
        cts.push(ct);
    }
}

fn rundreisen<const N: usize, const PK: usize, const SK: usize, const CT: usize>(
    kem: &KemGeneric<N, PK, SK, CT>,
    anzahl: usize,
    saat: u64,
) {
    let mut rng = Rng::new(saat);
    let mut pks: Vec<[u8; PK]> = Vec::new();
    for i in 0..anzahl {
        let (sa, ns, z, m) = (zufall32(&mut rng), zufall32(&mut rng), zufall32(&mut rng), zufall32(&mut rng));
        let (pk, sk) = kem.keygen_derand(&sa, &ns, &z);
        let (ct, ss) = kem.encaps_derand(&pk, &m);
        assert_eq!(kem.decaps(&sk, &ct), ss, "n={N}: Entschlüsselungsfehler in Runde {i}");
        assert!(!pks.contains(&pk), "n={N}: doppelter öffentlicher Schlüssel");
        pks.push(pk);
    }
}

#[test]
fn eig18_rundreisen_serie_ohne_entschluesselungsfehler() {
    rundreisen(&Kem512::new(), skaliert(1500, 60), 0x5E11E);
    rundreisen(&Kem1024::new(), skaliert(150, 6), 0x5E11F);
}

#[test]
fn eig19_manipulierter_oeffentlicher_schluessel_wird_vom_halter_erkannt() {
    // Wer an einen veränderten pk kapselt, erzeugt einen Chiffretext, den der
    // Halter des ORIGINAL-sk beim Re-Encrypt ablehnt (sk enthält das echte pk).
    let kem = Kem512::new();
    let mut rng = Rng::new(0x9A1);
    let (sa, ns, z, m) = (
        zufall32(&mut rng),
        zufall32(&mut rng),
        zufall32(&mut rng),
        zufall32(&mut rng),
    );
    let (pk, sk) = kem.keygen_derand(&sa, &ns, &z);
    let (_ct, ss_echt) = kem.encaps_derand(&pk, &m);

    let schritt = skaliert(1, 7);
    for bit in (0..PK_LEN * 8).step_by(schritt) {
        let mut pk2 = pk;
        kippe_bit(&mut pk2, bit);
        let (ct2, ss2) = kem.encaps_derand(&pk2, &m);
        let ss_halter = kem.decaps(&sk, &ct2);
        assert_ne!(ss_halter, ss2, "pk-Bit {bit}: Halter erhält das Secret des Angreifers");
        assert_ne!(ss_halter, ss_echt, "pk-Bit {bit}: Halter erhält das echte Secret");
    }
}

#[test]
fn eig20_zufalls_keygen_und_encaps_wiederholen_sich_nicht() {
    let kem = Kem512::new();
    let mut pks = Vec::new();
    let mut zs = Vec::new();
    for _ in 0..20 {
        let (pk, sk) = kem.keygen();
        assert!(!pks.contains(&pk), "keygen lieferte zweimal denselben pk");
        pks.push(pk);
        zs.push(sk[SK_LEN - 32..].to_vec());
    }
    for i in 0..zs.len() {
        for j in i + 1..zs.len() {
            assert_ne!(zs[i], zs[j], "z wiederholt sich");
        }
    }
    let (pk, sk) = kem.keygen();
    let (ct1, ss1) = kem.encaps(&pk);
    let (ct2, ss2) = kem.encaps(&pk);
    assert_ne!(ct1, ct2, "encaps ist nicht randomisiert");
    assert_ne!(ss1, ss2);
    assert_eq!(kem.decaps(&sk, &ct1), ss1);
    assert_eq!(kem.decaps(&sk, &ct2), ss2);
}

#[test]
fn eig21_fremder_chiffretext_ergibt_ablehnungs_secret_des_empfaengers() {
    // ct aus Schlüsselpaar A, entkapselt mit sk von B: kein Absturz, nicht das
    // Secret von A, sondern exakt SHAKE-256(z_B ‖ SHA3-256(ct)).
    let kem = Kem512::new();
    let mut rng = Rng::new(0xFEED);
    let (sa_a, ns_a, z_a, m) = (zufall32(&mut rng), zufall32(&mut rng), zufall32(&mut rng), zufall32(&mut rng));
    let (sa_b, ns_b, z_b) = (zufall32(&mut rng), zufall32(&mut rng), zufall32(&mut rng));
    let (pk_a, _sk_a) = kem.keygen_derand(&sa_a, &ns_a, &z_a);
    let (_pk_b, sk_b) = kem.keygen_derand(&sa_b, &ns_b, &z_b);
    let (ct, ss_a) = kem.encaps_derand(&pk_a, &m);

    let ss_b = kem.decaps(&sk_b, &ct);
    assert_ne!(ss_b, ss_a);
    let hc = sha3_256(&[&ct[..]]);
    assert_eq!(&ss_b[..], &shake256(&[&z_b[..], &hc[..]], SS_LEN)[..]);
}

// ═════════════════════ E. Totalität (kein Eingabe-Panik) ═════════════════

fn muster<const L: usize>(rng: &mut Rng) -> Vec<[u8; L]> {
    let mut v = vec![[0x00u8; L], [0xFFu8; L], [0x80u8; L], [0x7Fu8; L]];
    // Werte rund um q = 0x3001 (12289): 0x3000, 0x3001, 0x3002 als LE-Wörter
    for w in [0x3000u16, 0x3001, 0x3002, 0xEFFF, 0xF000] {
        let mut b = [0u8; L];
        for chunk in b.chunks_mut(2) {
            chunk[0] = (w & 0xFF) as u8;
            if chunk.len() > 1 {
                chunk[1] = (w >> 8) as u8;
            }
        }
        v.push(b);
    }
    for _ in 0..6 {
        let mut b = [0u8; L];
        rng.fill(&mut b);
        v.push(b);
    }
    v
}

fn totalitaet<const N: usize, const PK: usize, const SK: usize, const CT: usize>(
    kem: &KemGeneric<N, PK, SK, CT>,
    saat: u64,
) {
    let mut rng = Rng::new(saat);
    let m = zufall32(&mut rng);

    // encaps_derand gegen beliebige "öffentliche Schlüssel"
    for pk in muster::<PK>(&mut rng) {
        let (ct1, ss1) = kem.encaps_derand(&pk, &m);
        let (ct2, ss2) = kem.encaps_derand(&pk, &m);
        assert_eq!((ct1, ss1), (ct2, ss2), "n={N}: encaps nicht deterministisch");
    }
    // decaps mit beliebigen sk/ct-Kombinationen
    let sks = muster::<SK>(&mut rng);
    let cts = muster::<CT>(&mut rng);
    for sk in &sks {
        for ct in &cts {
            let a = kem.decaps(sk, ct);
            let b = kem.decaps(sk, ct);
            assert_eq!(a, b, "n={N}: decaps nicht deterministisch");
        }
    }
}

#[test]
fn eig22_totalitaet_n512() {
    totalitaet(&Kem512::new(), 0x70);
}

#[test]
fn eig23_totalitaet_n1024() {
    totalitaet(&Kem1024::new(), 0x71);
}

// ═════════════════════ F. Trait- und Registry-Schicht ════════════════════

#[test]
fn eig24_registry_rundreise_und_laengenfehler_beider_parametersaetze() {
    let reg = Registry::with_defaults();
    for (alg, pk_l, sk_l, ct_l) in [
        (Algorithm::ReKem512, PK_LEN, SK_LEN, CT_LEN),
        (Algorithm::ReKem1024, PK_LEN_1024, SK_LEN_1024, CT_LEN_1024),
    ] {
        let kem = reg.get(alg).expect("Algorithmus fehlt in der Registry");
        let kp = kem.keygen().unwrap();
        assert_eq!(kp.public_key.len(), pk_l);
        assert_eq!(kp.secret_key.len(), sk_l);
        let (ct, ss) = kem.encaps(&kp.public_key).unwrap();
        assert_eq!(ct.len(), ct_l);
        assert_eq!(ss.len(), SS_LEN);
        assert_eq!(kem.decaps(&kp.secret_key, &ct).unwrap(), ss);

        // Falsche Längen: leer, eins zu kurz, eins zu lang — für alle drei Objekte.
        for delta in [-1isize, 1] {
            let pk_bad = resize(&kp.public_key, delta);
            let sk_bad = resize(&kp.secret_key, delta);
            let ct_bad = resize(&ct, delta);
            assert!(matches!(kem.encaps(&pk_bad), Err(KemError::BadLength { what: "public key", .. })));
            assert!(matches!(kem.decaps(&sk_bad, &ct), Err(KemError::BadLength { what: "secret key", .. })));
            assert!(matches!(kem.decaps(&kp.secret_key, &ct_bad), Err(KemError::BadLength { what: "ciphertext", .. })));
        }
        assert!(matches!(kem.encaps(&[]), Err(KemError::BadLength { .. })));
        assert!(matches!(kem.decaps(&[], &[]), Err(KemError::BadLength { .. })));

        // Echter Chiffretext, fremder Schlüssel: nie das echte Secret.
        let kp2 = kem.keygen().unwrap();
        assert_ne!(kem.decaps(&kp2.secret_key, &ct).unwrap(), ss);
    }
}

fn resize(v: &[u8], delta: isize) -> Vec<u8> {
    let mut o = v.to_vec();
    if delta < 0 {
        o.pop();
    } else {
        o.push(0);
    }
    o
}

#[test]
fn eig25_parametersaetze_lassen_sich_nicht_vermischen() {
    let reg = Registry::with_defaults();
    let k512 = reg.get(Algorithm::ReKem512).unwrap();
    let k1024 = reg.get(Algorithm::ReKem1024).unwrap();
    let kp512 = k512.keygen().unwrap();
    let kp1024 = k1024.keygen().unwrap();
    let (ct512, _) = k512.encaps(&kp512.public_key).unwrap();

    // Schlüssel/Chiffretext des einen Satzes in den anderen: Längenfehler, kein Panik.
    assert!(matches!(k1024.encaps(&kp512.public_key), Err(KemError::BadLength { .. })));
    assert!(matches!(k512.encaps(&kp1024.public_key), Err(KemError::BadLength { .. })));
    assert!(matches!(
        k1024.decaps(&kp1024.secret_key, &ct512),
        Err(KemError::BadLength { what: "ciphertext", .. })
    ));
    assert!(matches!(
        k512.decaps(&kp1024.secret_key, &ct512),
        Err(KemError::BadLength { what: "secret key", .. })
    ));
}

#[test]
fn eig26_registry_verhalten_bei_unbekanntem_und_ersetztem_algorithmus() {
    let mut reg = Registry::new();
    assert!(reg.algorithms().is_empty());
    assert!(reg.get(Algorithm::ReKem512).is_none());
    assert!(reg.get_by_label("re-kem-512").is_none());

    reg.register(Box::new(re_kem_core::api::ReKemKem::new()));
    reg.register(Box::new(re_kem_core::api::ReKemKem::new())); // Ersetzen, nicht Verdoppeln
    assert_eq!(reg.algorithms(), vec![Algorithm::ReKem512]);
    assert_eq!(reg.labels(), vec!["re-kem-512".to_string()]);
    assert!(reg.get_by_label("re-kem-1024").is_none());
    assert!(reg.get(Algorithm::MlKem768).is_none());
}
