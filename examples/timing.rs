//! dudect-style timing analysis for the Rust KEM.
//!
//! dudect (Reparaz, Balasch, Verbauwhede) measures whether the execution time
//! of a routine depends on secret data. It runs the operation many times with
//! inputs drawn from two classes, records the wall-clock time for each run, and
//! applies Welch's t-test to the two distributions. A large |t| means the two
//! classes are distinguishable by timing — i.e. a leak. As a rule of thumb
//! |t| < 10 is considered "no leak detected".
//!
//! Two experiments are run here:
//!
//!   1. **Success vs. rejection path.** Class 0 decapsulates a valid
//!      ciphertext, class 1 a tampered one. This exercises the implicit
//!      rejection selection — the most secret-dependent control flow in the
//!      scheme.
//!   2. **Random secret keys.** Class 0 and class 1 use different secret keys,
//!      checking the general decapsulation path.
//!
//! Measurements are interleaved with a randomised class order to defeat
//! slow drift (CPU frequency, cache state), and the top/bottom percentile is
//! trimmed before computing the t-statistic to reduce outlier influence.
//!
//! Usage:
//!     MEASUREMENTS=100000 cargo run --release --example timing

use std::env;
use std::time::Instant;

use re_kem_core::{ReKem, CT_LEN, PK_LEN, SK_LEN};
use sha2::{Digest, Sha256};

/// Number of measurements per class, per experiment.
fn measurements() -> usize {
    env::var("MEASUREMENTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50_000)
}

/// Simple xorshift for deterministic class scheduling (not security relevant).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

fn derive_seed(label: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    Digest::update(&mut h, label.as_bytes());
    h.finalize().into()
}

/// Trimmed Welch t-test on two samples. Returns (t, n0, n1).
fn welch_t(a: &[f64], b: &[f64], trim: f64) -> (f64, usize, usize) {
    fn trimmed(v: &[f64], trim: f64) -> Vec<f64> {
        let mut s = v.to_vec();
        s.sort_by(|x, y| x.partial_cmp(y).unwrap());
        let k = ((s.len() as f64) * trim) as usize;
        if s.len() > 2 * k {
            s[k..s.len() - k].to_vec()
        } else {
            s
        }
    }
    let a = trimmed(a, trim);
    let b = trimmed(b, trim);
    let n0 = a.len() as f64;
    let n1 = b.len() as f64;
    let m0 = a.iter().sum::<f64>() / n0;
    let m1 = b.iter().sum::<f64>() / n1;
    let v0 = a.iter().map(|x| (x - m0).powi(2)).sum::<f64>() / (n0 - 1.0);
    let v1 = b.iter().map(|x| (x - m1).powi(2)).sum::<f64>() / (n1 - 1.0);
    let denom = (v0 / n0 + v1 / n1).sqrt();
    let t = if denom > 0.0 { (m0 - m1) / denom } else { 0.0 };
    (t, a.len(), b.len())
}

fn verdict(t: f64) -> &'static str {
    let a = t.abs();
    if a < 10.0 {
        "kein Leck erkennbar"
    } else if a < 50.0 {
        "Grenzbereich — verdächtig"
    } else {
        "LEAK VERDACHT"
    }
}

/// Experiment 1: valid ciphertext (class 0) vs. tampered ciphertext (class 1).
fn exp_rejection_path(kem: &ReKem, n: usize) -> (f64, usize, usize) {
    println!("--- Experiment 1: Erfolgs- vs. Zurückweisungspfad (decaps) ---");
    let (pk, sk): ([u8; PK_LEN], [u8; SK_LEN]) =
        kem.keygen_derand(&derive_seed("t1-a"), &derive_seed("t1-b"), &derive_seed("t1-c"));

    // Precompute a pool of valid ciphertexts and their tampered twins.
    let pool = 256usize;
    let mut valid: Vec<[u8; CT_LEN]> = Vec::with_capacity(pool);
    let mut tampered: Vec<[u8; CT_LEN]> = Vec::with_capacity(pool);
    for i in 0..pool {
        let (ct, _ss) = kem.encaps_derand(&pk, &derive_seed(&format!("t1-msg-{}", i)));
        let mut bad = ct;
        bad[i % CT_LEN] ^= 0x01;
        valid.push(ct);
        tampered.push(bad);
    }

    let mut rng = Rng(0x9E3779B97F4A7C15);
    let mut samp0: Vec<f64> = Vec::with_capacity(n);
    let mut samp1: Vec<f64> = Vec::with_capacity(n);

    // warm-up
    for _ in 0..1000 {
        std::hint::black_box(kem.decaps(&sk, &valid[0]));
    }

    for _ in 0..n {
        let class = rng.next() & 1;
        let idx = (rng.next() as usize) % pool;
        let ct = if class == 0 { &valid[idx] } else { &tampered[idx] };

        let t0 = Instant::now();
        let out = kem.decaps(&sk, ct);
        let dt = t0.elapsed().as_nanos() as f64;
        std::hint::black_box(out);

        if class == 0 {
            samp0.push(dt);
        } else {
            samp1.push(dt);
        }

        if samp0.len() % 10_000 == 0 && samp1.len() == samp0.len() && !samp0.is_empty() {
            let (t, _, _) = welch_t(&samp0, &samp1, 0.01);
            eprintln!("  n={:>7}  t = {:>8.2}  [{}]", samp0.len(), t, verdict(t));
        }
    }

    let (t, n0, n1) = welch_t(&samp0, &samp1, 0.01);
    println!("  Messungen: {} / {}", n0, n1);
    println!("  t-Statistik: {:.2}", t);
    println!("  Bewertung: {}", verdict(t));
    println!();
    (t, n0, n1)
}

/// Experiment 2: two different secret keys (class 0 vs. class 1).
fn exp_secret_keys(kem: &ReKem, n: usize) -> (f64, usize, usize) {
    println!("--- Experiment 2: verschiedene geheime Schlüssel (decaps) ---");
    let sk_a: [u8; SK_LEN] = {
        let (_, sk) = kem.keygen_derand(&derive_seed("t2-a"), &derive_seed("t2-b"), &derive_seed("t2-c"));
        sk
    };
    let sk_b: [u8; SK_LEN] = {
        let (_, sk) = kem.keygen_derand(&derive_seed("t2-d"), &derive_seed("t2-e"), &derive_seed("t2-f"));
        sk
    };
    let pk_a: [u8; PK_LEN] = {
        let (pk, _) = kem.keygen_derand(&derive_seed("t2-a"), &derive_seed("t2-b"), &derive_seed("t2-c"));
        pk
    };

    let pool = 256usize;
    let mut cts: Vec<[u8; CT_LEN]> = Vec::with_capacity(pool);
    for i in 0..pool {
        let (ct, _) = kem.encaps_derand(&pk_a, &derive_seed(&format!("t2-msg-{}", i)));
        cts.push(ct);
    }

    let mut rng = Rng(0xD1B54A32D192ED03);
    let mut samp0: Vec<f64> = Vec::with_capacity(n);
    let mut samp1: Vec<f64> = Vec::with_capacity(n);

    for _ in 0..1000 {
        std::hint::black_box(kem.decaps(&sk_a, &cts[0]));
    }

    for _ in 0..n {
        let class = rng.next() & 1;
        let idx = (rng.next() as usize) % pool;
        let sk = if class == 0 { &sk_a } else { &sk_b };

        let t0 = Instant::now();
        let out = kem.decaps(sk, &cts[idx]);
        let dt = t0.elapsed().as_nanos() as f64;
        std::hint::black_box(out);

        if class == 0 {
            samp0.push(dt);
        } else {
            samp1.push(dt);
        }

        if samp0.len() % 10_000 == 0 && samp1.len() == samp0.len() && !samp0.is_empty() {
            let (t, _, _) = welch_t(&samp0, &samp1, 0.01);
            eprintln!("  n={:>7}  t = {:>8.2}  [{}]", samp0.len(), t, verdict(t));
        }
    }

    let (t, n0, n1) = welch_t(&samp0, &samp1, 0.01);
    println!("  Messungen: {} / {}", n0, n1);
    println!("  t-Statistik: {:.2}", t);
    println!("  Bewertung: {}", verdict(t));
    println!();
    (t, n0, n1)
}

fn main() {
    let n = measurements();
    let kem = ReKem::new();

    println!("═══════════════════════════════════════════════════════");
    println!("  dudect-Style Timing-Analyse (RE-KEM, Rust-Kern)");
    println!("═══════════════════════════════════════════════════════");
    println!("Messungen pro Klasse und Experiment: {}", n);
    println!("Schwelle: |t| < 10 gilt als 'kein Leck erkennbar'");
    println!("Ausreißer: oberste/unterste 1 % je Klasse entfernt");
    println!();

    let (t1, _, _) = exp_rejection_path(&kem, n);
    let (t2, _, _) = exp_secret_keys(&kem, n);

    println!("═══════════════════════════════════════════════════════");
    println!("  ZUSAMMENFASSUNG");
    println!("═══════════════════════════════════════════════════════");
    println!("  Zurückweisungspfad:   t = {:>8.2}   {}", t1, verdict(t1));
    println!("  Verschiedene SK:      t = {:>8.2}   {}", t2, verdict(t2));
    println!("═══════════════════════════════════════════════════════");

    if t1.abs() < 10.0 && t2.abs() < 10.0 {
        println!("✅ Kein Timing-Leck in diesen Experimenten nachgewiesen.");
        println!("   Hinweis: fehlender Nachweis != Beweis fehlenden Lecks. dudect");
        println!("   ist eine statistische Heuristik; Wiederholung auf der Ziel-");
        println!("   plattform mit hoher Messzahl bleibt empfohlen.");
    } else {
        println!("❌ Mindestens ein Experiment zeigt Auffälligkeiten (|t| >= 10).");
        std::process::exit(1);
    }
}
