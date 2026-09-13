//! Rust side of the round-based cross-validation against the Python reference.
//!
//! Derives seeds identically to `tools/cross_kem_python.py`, runs the full KEM
//! deterministically, and emits the SHA-256 of pk, the SHA-256 of the
//! ciphertext, and the shared secret for each round.
//!
//! Usage:
//!     cargo run --release --example cross_kem > /tmp/rs-vectors.json
//!     DIM=1024 ROUNDS=1000 cargo run --release --example cross_kem > /tmp/rs-1024.json
//!
//! The seed labels are deliberately dimension-independent: the n=512 vector
//! set is frozen by the published cross-validation, so its labels must not
//! change. n=1024 uses the same labels — the derived keys differ because the
//! ring differs, which is what the comparison is meant to show.

use std::time::Instant;

use re_kem_core::{
    KemGeneric, ReKem, ReKem1024,
};
use sha2::{Digest, Sha256};

/// Ring dimension, overridable: `DIM=1024 ...`
fn dim() -> usize {
    std::env::var("DIM")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(512)
}

/// Round count, overridable: `ROUNDS=10000 ...`
fn rounds() -> usize {
    std::env::var("ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1000)
}

/// Identical seed derivation as the Python side:
///     sha256(label) -> 32 bytes
fn derive_seed(label: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    Digest::update(&mut h, label.as_bytes());
    h.finalize().into()
}

fn hex_sha256(data: &[u8]) -> String {
    let mut h = Sha256::new();
    Digest::update(&mut h, data);
    hex::encode(h.finalize())
}

fn run<const N: usize, const PK: usize, const SK: usize, const CT: usize>(
    kem: &KemGeneric<N, PK, SK, CT>,
    rounds: usize,
) {
    assert!(
        kem.sizes_are_consistent(),
        "const parameters are inconsistent for n={N}"
    );
    let start = Instant::now();

    let mut out = String::from("[\n");
    for i in 0..rounds {
        let seed_a = derive_seed(&format!("re-kem-cross-{}-seedA", i));
        let noise = derive_seed(&format!("re-kem-cross-{}-noise", i));
        let z = derive_seed(&format!("re-kem-cross-{}-z", i));
        let m = derive_seed(&format!("re-kem-cross-{}-msg", i));

        let (pk, sk): ([u8; PK], [u8; SK]) = kem.keygen_derand(&seed_a, &noise, &z);
        let (ct, ss): ([u8; CT], [u8; 32]) = kem.encaps_derand(&pk, &m);

        // self-check: decapsulation must recover the same secret
        let ss2 = kem.decaps(&sk, &ct);
        assert_eq!(ss, ss2, "Rust roundtrip failed at n={} i={}", N, i);

        let pk_hash = hex_sha256(&pk);
        let ct_hash = hex_sha256(&ct);
        let ss_hex = hex::encode(ss);

        out.push_str(&format!(
            "{{\"i\":{},\"pk_sha\":\"{}\",\"ct_sha\":\"{}\",\"ss\":\"{}\"}}",
            i, pk_hash, ct_hash, ss_hex
        ));
        if i + 1 < rounds {
            out.push(',');
        }
        if (i + 1) % 10 == 0 {
            out.push('\n');
        }
    }
    out.push_str("\n]\n");
    print!("{}", out);

    let dt = start.elapsed().as_secs_f64();
    eprintln!(
        "# Rust n={}: {} Runden in {:.1}s ({:.2} ms/Runde)",
        N,
        rounds,
        dt,
        dt / rounds as f64 * 1000.0
    );
}

fn main() {
    let rounds = rounds();
    match dim() {
        512 => run(&ReKem::new(), rounds),
        1024 => run(&ReKem1024::new(), rounds),
        d => panic!("DIM={d} has no parameter set"),
    }
}
