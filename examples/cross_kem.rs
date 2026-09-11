//! Rust side of the 1000-round cross-validation against the Python reference.
//!
//! Derives seeds identically to `tools/cross_kem_python.py`, runs the full
//! KEM deterministically, and emits the SHA-256 of pk, the SHA-256 of the
//! ciphertext, and the shared secret for each round.
//!
//! Usage:
//!     cargo run --release --example cross_kem > /tmp/rs-vectors.json

use std::time::Instant;

use re_kem_core::{ReKem, CT_LEN, PK_LEN, SK_LEN};
use sha2::{Digest, Sha256};

const ROUNDS: usize = 1000;

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

fn main() {
    let kem = ReKem::new();
    let start = Instant::now();

    let mut out = String::from("[\n");
    for i in 0..ROUNDS {
        let seed_a = derive_seed(&format!("re-kem-cross-{}-seedA", i));
        let noise = derive_seed(&format!("re-kem-cross-{}-noise", i));
        let z = derive_seed(&format!("re-kem-cross-{}-z", i));
        let m = derive_seed(&format!("re-kem-cross-{}-msg", i));

        let (pk, sk): ([u8; PK_LEN], [u8; SK_LEN]) = kem.keygen_derand(&seed_a, &noise, &z);
        let (ct, ss): ([u8; CT_LEN], [u8; 32]) = kem.encaps_derand(&pk, &m);

        // self-check: decapsulation must recover the same secret
        let ss2 = kem.decaps(&sk, &ct);
        assert_eq!(ss, ss2, "Rust roundtrip failed at i={}", i);

        let pk_hash = hex_sha256(&pk);
        let ct_hash = hex_sha256(&ct);
        let ss_hex = hex::encode(ss);

        out.push_str(&format!(
            "{{\"i\":{},\"pk_sha\":\"{}\",\"ct_sha\":\"{}\",\"ss\":\"{}\"}}",
            i, pk_hash, ct_hash, ss_hex
        ));
        if i + 1 < ROUNDS {
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
        "# Rust: {} Runden in {:.1}s ({:.1} ms/Runde)",
        ROUNDS,
        dt,
        dt / ROUNDS as f64 * 1000.0
    );
}
