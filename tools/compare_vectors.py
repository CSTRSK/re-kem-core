#!/usr/bin/env python3
"""Vergleicht Rust- und Python-Vektoren (beliebige Anzahl)."""
import json
import sys

RS = sys.argv[1] if len(sys.argv) > 1 else "/tmp/rs-10k.json"
PY = sys.argv[2] if len(sys.argv) > 2 else "/tmp/py-10k.json"

rs = json.load(open(RS))
py = json.load(open(PY))

print(f"Rust:   {len(rs)} Vektoren")
print(f"Python: {len(py)} Vektoren")
assert len(rs) == len(py), "Unterschiedliche Anzahl!"
print()

mpk, mct, mss = [], [], []
for a, b in zip(rs, py):
    assert a["i"] == b["i"]
    if a["pk_sha"] != b["pk_sha"]:
        mpk.append(a["i"])
    if a["ct_sha"] != b["ct_sha"]:
        mct.append(a["i"])
    if a["ss"] != b["ss"]:
        mss.append(a["i"])

total = len(rs) * 3
fails = len(mpk) + len(mct) + len(mss)

print(f"{'Feld':<16}{'Abweichungen':>14}")
print("-" * 30)
print(f"{'pk (SHA-256)':<16}{len(mpk):>14}")
print(f"{'ct (SHA-256)':<16}{len(mct):>14}")
print(f"{'shared secret':<16}{len(mss):>14}")
print("-" * 30)
print(f"{'GESAMT':<16}{fails:>10} / {total}")
print()

if fails == 0:
    print(f"✅ {len(rs)} Runden bit-identisch (Rust == Python), 0 Abweichungen.")
    print()
    for idx in [0, len(rs) // 2, len(rs) - 1]:
        print(f"  i={idx:>6}  pk={rs[idx]['pk_sha'][:20]}…  ss={rs[idx]['ss'][:20]}…")
else:
    print("❌ Abweichungen:")
    print(f"  pk: {mpk[:5]}  ct: {mct[:5]}  ss: {mss[:5]}")
    sys.exit(1)
