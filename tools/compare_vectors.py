#!/usr/bin/env python3
"""Vergleicht die 1000 Rust- und Python-Vektoren."""
import hashlib
import json

RS = "/tmp/rs-vectors.json"
PY = "/tmp/py-vectors.json"

rs = json.load(open(RS))
py = json.load(open(PY))

print("=== Umfang ===")
print(f"Rust:   {len(rs)} Vektoren")
print(f"Python: {len(py)} Vektoren")
print()

assert len(rs) == len(py) == 1000, "Unterschiedliche Anzahl!"

mismatch_pk = []
mismatch_ct = []
mismatch_ss = []

for a, b in zip(rs, py):
    assert a["i"] == b["i"], "Index-Versatz"
    if a["pk_sha"] != b["pk_sha"]:
        mismatch_pk.append(a["i"])
    if a["ct_sha"] != b["ct_sha"]:
        mismatch_ct.append(a["i"])
    if a["ss"] != b["ss"]:
        mismatch_ss.append(a["i"])

total_checks = len(rs) * 3
total_fail = len(mismatch_pk) + len(mismatch_ct) + len(mismatch_ss)

print("=== Ergebnisse (1000 Runden) ===")
print(f"{'Feld':<12} {'Abweichungen':>14}")
print(f"{'-'*28}")
print(f"{'pk (SHA-256)':<12} {len(mismatch_pk):>14}")
print(f"{'ct (SHA-256)':<12} {len(mismatch_ct):>14}")
print(f"{'shared secret':<12} {len(mismatch_ss):>14}")
print(f"{'-'*28}")
print(f"{'GESAMT':<12} {total_fail:>10} / {total_checks}")
print()

if total_fail == 0:
    print("✅ PERFEKT: Rust und Python sind in ALLEN 1000 Runden bit-identisch.")
    print("   (pk, ciphertext UND shared secret — inklusive NTT, CBD, Rejection-Sampling,")
    print("    FO-Transform und Serialisierung)")
    print()
    # Stichproben als Beleg
    print("Stichproben (i = 0, 499, 999):")
    for idx in [0, 499, 999]:
        r, p = rs[idx], py[idx]
        print(f"  i={idx:>4}  pk={r['pk_sha'][:16]}…  ct={r['ct_sha'][:16]}…  ss={r['ss'][:16]}…")
        print(f"          {'':>4}  pk={p['pk_sha'][:16]}…  ct={p['ct_sha'][:16]}…  ss={p['ss'][:16]}…")
else:
    print("❌ ABWEICHUNGEN:")
    for label, lst in [("pk", mismatch_pk), ("ct", mismatch_ct), ("ss", mismatch_ss)]:
        if lst:
            print(f"  {label}: {len(lst)} Abweichungen, erste: {lst[:10]}")
    print()
    i = (mismatch_pk + mismatch_ct + mismatch_ss)[0]
    print(f"Beispiel i={i}:")
    print("  Rust:  ", rs[i])
    print("  Python:", py[i])
