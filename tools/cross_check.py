#!/usr/bin/env python3
"""
Cross-Validation: Rust `re-kem-core` vs. Python reference.

Reads the deterministic vector set emitted by
    cargo run --release --example cross_vectors > /tmp/vectors.json
and recomputes every operation with plain modular arithmetic (the Python
reference's `% self.q` approach). Any disagreement means the Rust Montgomery
arithmetic (or a constant like R²) is wrong.

Usage:
    python3 tools/cross_check.py /tmp/vectors.json
"""
import json
import sys


def main():
    if len(sys.argv) < 2:
        print("Usage: cross_check.py <vectors.json>")
        return 1

    with open(sys.argv[1], encoding="utf-8") as f:
        data = json.load(f)

    q = data["q"]
    vectors = data["vectors"]
    print(f"=== Cross-Validation: Rust (Montgomery) vs. Python (naive mod q) ===")
    print(f"Modulus q = {q} | {len(vectors)} Vektoren")
    print()

    checked = 0
    fails = []

    for v in vectors:
        a, b = v["a"], v["b"]
        exp_add = (a + b) % q
        exp_sub = (a - b) % q
        exp_mul = (a * b) % q

        if v["add"] != exp_add:
            fails.append(f"add a={a} b={b}: rust={v['add']} py={exp_add}")
        if v["sub"] != exp_sub:
            fails.append(f"sub a={a} b={b}: rust={v['sub']} py={exp_sub}")
        if v["mul"] != exp_mul:
            fails.append(f"mul a={a} b={b}: rust={v['mul']} py={exp_mul}")
        checked += 3

    print(f"Geprüfte Operationen: {checked}")
    print(f"Fehlgeschlagen:       {len(fails)}")
    print()

    if fails:
        print("❌ ABWEICHUNGEN GEFUNDEN:")
        for f_ in fails[:15]:
            print(f"  {f_}")
        if len(fails) > 15:
            print(f"  ... und {len(fails) - 15} weitere")
        return 1

    print("✅ Rust und Python stimmen in ALLEN Operationen überein.")

    # Show a few sample vectors as evidence
    print()
    print("Beispiel-Vektoren (letzte 3):")
    for v in vectors[-3:]:
        print(f"  a={v['a']:>5} b={v['b']:>5} → add={v['add']:>5} sub={v['sub']:>5} mul={v['mul']:>5}")
    print()
    print("Damit ist die Rust-Montgomery-Arithmetik gegen die Python-Referenz")
    print("verifiziert (inkl. der korrigierten R²-Konstante).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
