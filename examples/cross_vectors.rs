//! Emits deterministic test vectors for cross-validation against the Python
//! reference implementation (`rekem.py` / RE-KEM).
//!
//! The vector set is generated from a fixed arithmetic progression so that the
//! Python side can reproduce it exactly without shipping a data file.
//!
//! Usage:
//!     cargo run --release --example cross_vectors > /tmp/vectors.json

use re_kem_core::{FieldElement, Q};

/// Deterministic, reproducible sample set including edge cases.
fn samples() -> Vec<u16> {
    let mut v: Vec<u16> = (0..200u32)
        .map(|i| ((i * 257 + 13) % Q) as u16)
        .collect();
    // Edge cases: 0, 1, 2, q-1, q-2, q/2, q/2 ± 1
    v.extend_from_slice(&[
        0,
        1,
        2,
        (Q - 1) as u16,
        (Q - 2) as u16,
        (Q / 2) as u16,
        (Q / 2 - 1) as u16,
        (Q / 2 + 1) as u16,
    ]);
    v
}

fn main() {
    let vals = samples();
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str(&format!("  \"q\": {},\n", Q));
    out.push_str(&format!("  \"modulus_q\": {},\n", Q));
    out.push_str("  \"vectors\": [\n");

    let mut first = true;
    // Cross-product over a smaller slice for pair-wise ops (keeps output sane),
    // plus the full list against a fixed partner.
    for &a in vals.iter() {
        for &b in vals.iter().step_by(7) {
            let fe_a = FieldElement::from_plain(a);
            let fe_b = FieldElement::from_plain(b);
            let add = fe_a.add(fe_b).to_plain();
            let sub = fe_a.sub(fe_b).to_plain();
            let mul = fe_a.mul(fe_b).to_plain();

            if !first {
                out.push_str(",\n");
            }
            first = false;
            out.push_str(&format!(
                "    {{\"a\": {}, \"b\": {}, \"add\": {}, \"sub\": {}, \"mul\": {}}}",
                a, b, add, sub, mul
            ));
        }
    }

    out.push_str("\n  ]\n}\n");
    println!("{}", out);
}
