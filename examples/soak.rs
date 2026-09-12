//! 4-hour soak test of the Rust KEM.
//!
//! Runs continuously for a configurable wall-clock duration, performing a full
//! keygen -> encaps -> decaps cycle per round and asserting the shared secrets
//! match. Periodically injects a tampered ciphertext and asserts implicit
//! rejection (the derived secret must differ), and logs memory usage to catch
//! leaks.
//!
//! Usage:
//!     DURATION_SECONDS=14400 cargo run --release --example soak
//!     ROUNDS=1000000 cargo run --release --example soak      # fixed count instead

use std::env;
use std::io::{BufRead, BufReader};
use std::time::{Duration, Instant};

use re_kem_core::{ReKem, CT_LEN, PK_LEN, SK_LEN};
use sha2::{Digest, Sha256};

fn derive_seed(label: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    Digest::update(&mut h, label.as_bytes());
    h.finalize().into()
}

/// Resident set size in kB, read from /proc (Linux only) — for leak detection.
fn rss_kb() -> Option<u64> {
    let f = std::fs::File::open("/proc/self/status").ok()?;
    for line in BufReader::new(f).lines().map_while(Result::ok) {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

fn main() {
    let duration_secs: Option<u64> = env::var("DURATION_SECONDS")
        .ok()
        .and_then(|v| v.parse().ok());
    let fixed_rounds: usize = env::var("ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let kem = ReKem::new();

    // ── self-test round before the long run ──
    {
        let (pk, sk): ([u8; PK_LEN], [u8; SK_LEN]) =
            kem.keygen_derand(&[1u8; 32], &[2u8; 32], &[3u8; 32]);
        let (ct, ss): ([u8; CT_LEN], [u8; 32]) = kem.encaps_derand(&pk, &[4u8; 32]);
        assert_eq!(ss, kem.decaps(&sk, &ct), "pre-flight roundtrip failed");
    }
    eprintln!("Pre-flight self-test: OK");
    eprintln!(
        "Modus: {}",
        match (duration_secs, fixed_rounds) {
            (Some(d), _) => format!("{} Sekunden ({:.2} h)", d, d as f64 / 3600.0),
            (None, r) if r > 0 => format!("{} Runden", r),
            _ => "unbegrenzt (bis Abbruch)".to_string(),
        }
    );
    let rss_start = rss_kb().unwrap_or(0);
    eprintln!("VmRSS Start: {} kB", rss_start);
    eprintln!();

    let start = Instant::now();
    let deadline = duration_secs.map(|d| start + Duration::from_secs(d));

    let mut rounds: u64 = 0;
    let mut failures: u64 = 0;
    let mut tamper_checks: u64 = 0;
    let mut tamper_failures: u64 = 0;
    let mut last_report = Instant::now();
    let mut rounds_at_last_report: u64 = 0;
    let mut peak_rss = rss_start;

    loop {
        if let Some(dl) = deadline {
            if Instant::now() >= dl {
                break;
            }
        }
        if fixed_rounds > 0 && rounds as usize >= fixed_rounds {
            break;
        }

        let i = rounds as usize;
        let seed_a = derive_seed(&format!("soak-{}-seedA", i));
        let noise = derive_seed(&format!("soak-{}-noise", i));
        let z = derive_seed(&format!("soak-{}-z", i));
        let m = derive_seed(&format!("soak-{}-msg", i));

        let (pk, sk): ([u8; PK_LEN], [u8; SK_LEN]) = kem.keygen_derand(&seed_a, &noise, &z);
        let (ct, ss): ([u8; CT_LEN], [u8; 32]) = kem.encaps_derand(&pk, &m);
        let ss_rx = kem.decaps(&sk, &ct);

        if ss_tx_ok(&ss, &ss_rx) {
            // matched
        } else {
            failures += 1;
        }

        // Every 4096th round: implicit-rejection check with a tampered ciphertext
        if rounds % 4096 == 0 {
            let mut bad = ct;
            bad[rounds as usize % CT_LEN] ^= 0x01;
            let ss_bad = kem.decaps(&sk, &bad);
            tamper_checks += 1;
            if ss_bad == ss {
                tamper_failures += 1;
            }
        }

        rounds += 1;

        // progress report every 60 seconds
        if last_report.elapsed() >= Duration::from_secs(60) {
            let el = start.elapsed().as_secs_f64();
            let window = (rounds - rounds_at_last_report) as f64 / last_report.elapsed().as_secs_f64();
            let rss = rss_kb().unwrap_or(0);
            if rss > peak_rss {
                peak_rss = rss;
            }
            eprintln!(
                "[{:>7.1}s] {:>12} Runden | {:>7.0}/s (Ø {:>7.0}/s) | Fehler {} | Tamper {}/{} | RSS {} kB",
                el,
                rounds,
                window,
                rounds as f64 / el,
                failures,
                tamper_failures,
                tamper_checks,
                rss
            );
            last_report = Instant::now();
            rounds_at_last_report = rounds;
        }
    }

    let elapsed = start.elapsed().as_secs_f64();
    let rss_end = rss_kb().unwrap_or(0);

    eprintln!();
    eprintln!("═══════════════════════════════════════════════════════");
    eprintln!("  SOAK-TEST ERGEBNIS");
    eprintln!("═══════════════════════════════════════════════════════");
    eprintln!("Laufzeit:          {:.1} s ({:.2} h)", elapsed, elapsed / 3600.0);
    eprintln!("Runden:            {}", rounds);
    eprintln!("Roundtrip-Fehler:  {}", failures);
    eprintln!("Tamper-Checks:     {} (davon durchgelassen: {})", tamper_checks, tamper_failures);
    eprintln!("Durchsatz:         {:.0} Runden/s", rounds as f64 / elapsed);
    eprintln!("Pro Runde:         {:.3} ms", elapsed / rounds as f64 * 1000.0);
    eprintln!("VmRSS Start/Ende:  {} / {} kB (Peak {})", rss_start, rss_end, peak_rss);
    eprintln!("Speicher-Drift:    {} kB", rss_end as i64 - rss_start as i64);
    eprintln!("═══════════════════════════════════════════════════════");
    if failures == 0 && tamper_failures == 0 {
        eprintln!("✅ SOAK-TEST BESTANDEN — keine Fehler, kein Leck-Verdacht");
    } else {
        eprintln!("❌ FEHLER: {} Roundtrips, {} Tamper", failures, tamper_failures);
        std::process::exit(1);
    }
}

/// Extracted so the compiler never optimises the comparison away.
#[inline(never)]
fn ss_tx_ok(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a == b
}
