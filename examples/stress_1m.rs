//! 1-000-000-round stress test of the Rust KEM.
//!
//! Each round performs a full keygen -> encaps -> decaps cycle and asserts
//! that the shared secrets match. Optionally emits the first `EMIT` rounds as
//! vectors for the Python cross-check.
//!
//! Usage:
//!     ROUNDS=1000000 EMIT=0 cargo run --release --example stress_1m
//!     ROUNDS=1000000 EMIT=10000 cargo run --release --example stress_1m > /tmp/rs-10k.json

use std::env;
use std::time::Instant;

use re_kem_core::ReKem;
use sha2::{Digest, Sha256};

fn derive_seed(label: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    Digest::update(&mut h, label.as_bytes());
    h.finalize().into()
}

fn main() {
    let rounds: usize = env::var("ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1_000_000);
    let emit: usize = env::var("EMIT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let kem = ReKem::new();

    eprintln!("=== RE-KEM Rust-Stresstest ===");
    eprintln!("Runden:  {}", rounds);
    eprintln!("Emit:    {} Vektoren (für Python-Abgleich)", emit);
    eprintln!();

    let mut failures: usize = 0;
    let first_failure: Option<usize> = None;
    let mut first_failure = first_failure;

    let mut emit_buf = String::from("[\n");
    let mut emitted = 0usize;

    let start = Instant::now();
    for i in 0..rounds {
        let seed_a = derive_seed(&format!("re-kem-cross-{}-seedA", i));
        let noise = derive_seed(&format!("re-kem-cross-{}-noise", i));
        let z = derive_seed(&format!("re-kem-cross-{}-z", i));
        let m = derive_seed(&format!("re-kem-cross-{}-msg", i));

        let (pk, sk) = kem.keygen_derand(&seed_a, &noise, &z);
        let (ct, ss_tx) = kem.encaps_derand(&pk, &m);
        let ss_rx = kem.decaps(&sk, &ct);

        if ss_tx != ss_rx {
            failures += 1;
            if first_failure.is_none() {
                first_failure = Some(i);
            }
        }

        if emitted < emit {
            let pk_h = {
                let mut h = Sha256::new();
                Digest::update(&mut h, &pk);
                hex::encode(h.finalize())
            };
            let ct_h = {
                let mut h = Sha256::new();
                Digest::update(&mut h, &ct);
                hex::encode(h.finalize())
            };
            if emitted > 0 {
                emit_buf.push(',');
            }
            emit_buf.push_str(&format!(
                "{{\"i\":{},\"pk_sha\":\"{}\",\"ct_sha\":\"{}\",\"ss\":\"{}\"}}",
                i,
                pk_h,
                ct_h,
                hex::encode(ss_tx)
            ));
            emitted += 1;
        }

        if (i + 1) % 100_000 == 0 {
            let el = start.elapsed().as_secs_f64();
            eprintln!(
                "  {:>9} / {} Runden  ({:.1}s, {:.1} Runden/s, Fehler: {})",
                i + 1,
                rounds,
                el,
                (i + 1) as f64 / el,
                failures
            );
        }
    }
    let elapsed = start.elapsed().as_secs_f64();

    if emit > 0 {
        emit_buf.push_str("\n]\n");
        print!("{}", emit_buf);
    }

    eprintln!();
    eprintln!("=== Ergebnis ===");
    eprintln!("Runden:        {}", rounds);
    eprintln!("Fehler:        {}", failures);
    if let Some(f) = first_failure {
        eprintln!("Erster Fehler: i={}", f);
    }
    eprintln!("Dauer:         {:.1}s", elapsed);
    eprintln!("Durchsatz:     {:.0} Runden/s", rounds as f64 / elapsed);
    eprintln!(
        "Pro Runde:     {:.3} ms (keygen + encaps + decaps)",
        elapsed / rounds as f64 * 1000.0
    );
    eprintln!();
    if failures == 0 {
        eprintln!("✅ ALLE {} RUNDEN KORREKT", rounds);
    } else {
        eprintln!("❌ {} FEHLER", failures);
        std::process::exit(1);
    }
}
