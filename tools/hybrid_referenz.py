#!/usr/bin/env python3
"""Unabhaengige Referenz fuer den Hybrid-Kombinierer.

Rechnet SHA3-256(PRAEFIX || id || pq_ss || x_ss || pq_ct || x_ct || x_pk)
in reinem Python nach und schreibt Vektoren als JSON.

Aufruf:
    python3 tools/hybrid_referenz.py            # schreibt tests/hybrid_kombinierer.json
    python3 tools/hybrid_referenz.py --print    # gibt die Vektoren auf stdout aus
"""
import hashlib
import json
import sys
import pathlib

PRAEFIX = b"re-kem-core/hybrid/v1"


def kombinierer(algo_id: int, pq_ss: bytes, x_ss: bytes,
                pq_ct: bytes, x_ct: bytes, x_pk: bytes) -> bytes:
    """Genau die Spezifikation: Reihenfolge und Laengen sind verbindlich."""
    h = hashlib.sha3_256()
    h.update(PRAEFIX)
    h.update(bytes([algo_id]))
    h.update(pq_ss)
    h.update(x_ss)
    h.update(pq_ct)
    h.update(x_ct)
    h.update(x_pk)
    return h.digest()


def vektoren() -> list:
    """20 feste Vektoren, deterministisch aus Zaehler abgeleitet."""
    out = []
    for i in range(20):
        algo = 0x81 if i % 2 == 0 else 0x90
        # Feste, aber unterschiedliche Eingaben je Vektor
        pq_ss = bytes([(i * 7 + j) % 256 for j in range(32)])
        x_ss = bytes([(i * 13 + j) % 256 for j in range(32)])
        # pq_ct-Laenge je Algorithmus: 2048 bzw. 1088
        pq_ct_len = 2048 if algo == 0x81 else 1088
        pq_ct = bytes([(i * 3 + j) % 256 for j in range(pq_ct_len)])
        x_ct = bytes([(i * 11 + j) % 256 for j in range(32)])
        x_pk = bytes([(i * 17 + j) % 256 for j in range(32)])

        out.append({
            "id": algo,
            "pq_ss": pq_ss.hex(),
            "x_ss": x_ss.hex(),
            "pq_ct_len": pq_ct_len,
            "pq_ct_first": pq_ct[:16].hex(),
            "pq_ct_last": pq_ct[-16:].hex(),
            "x_ct": x_ct.hex(),
            "x_pk": x_pk.hex(),
            "ss": kombinierer(algo, pq_ss, x_ss, pq_ct, x_ct, x_pk).hex(),
        })
    return out


def main() -> int:
    v = vektoren()
    if "--print" in sys.argv:
        print(json.dumps(v, indent=2))
        return 0
    ziel = pathlib.Path(__file__).resolve().parent.parent / "tests" / "hybrid_kombinierer.json"
    ziel.write_text(json.dumps(v, indent=2), encoding="utf-8")
    print(f"{len(v)} Vektoren geschrieben nach {ziel}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
