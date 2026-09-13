#!/usr/bin/env python3
"""
Python-Seite der 1000er-Cross-Validation.

Rechnet mit der Python-Referenz deterministisch (explizite Seeds) und
schreibt pro Iteration die Hashes von pk, ct und das Shared Secret.
Die Rust-Seite (examples/cross_kem.rs) rechnet mit denselben Seeds — die
Ergebnisse müssen bit-identisch sein.

Usage:
    python3 tools/cross_kem_python.py [rounds] [dim]
        rounds  — default 1000
        dim     — ring dimension, default 512

The Rust side is `examples/cross_kem.rs` with the same ROUNDS / DIM.
"""
import hashlib
import json
import sys
import time

sys.path.insert(0, "/root/RE-KEM")
from rekem import PostQuantumRingLWEKEM


def derive_seed(label: str) -> bytes:
    """Identische Seed-Ableitung wie in der Rust-Seite."""
    return hashlib.sha256(label.encode()).digest()


def main():
    rounds = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
    dim = int(sys.argv[2]) if len(sys.argv) > 2 else 512
    kem = PostQuantumRingLWEKEM(n=dim, q=12289, eta=8)
    out = []
    t0 = time.time()

    for i in range(rounds):
        seed_a = derive_seed(f"re-kem-cross-{i}-seedA")
        noise = derive_seed(f"re-kem-cross-{i}-noise")
        z = derive_seed(f"re-kem-cross-{i}-z")
        m = derive_seed(f"re-kem-cross-{i}-msg")

        # ── keygen (entspricht ReKem::keygen_derand) ──
        a = kem._expand_a(seed_a)
        s = kem._cbd_sample(noise, nonce=0)
        e = kem._cbd_sample(noise, nonce=1)
        b = (kem._poly_mul_ntt(a, s) + e) % kem.q
        pk = seed_a + kem._encode_poly(b)
        h_pk = hashlib.sha3_256(pk).digest()
        sk = kem._encode_poly(s) + pk + h_pk + z

        # ── encaps (entspricht ReKem::encaps_derand) ──
        g_out = hashlib.sha3_512(m + h_pk).digest()
        k_bar, coins = g_out[:32], g_out[32:]
        ct = kem._pke_encrypt(pk, m, coins)
        h_c = hashlib.sha3_256(ct).digest()
        ss = hashlib.shake_256(k_bar + h_c).digest(32)

        # ── decaps (Gegenprobe) ──
        ss2 = kem.decaps(sk, ct)
        assert ss == ss2, f"Python-Roundtrip fehlgeschlagen bei i={i}"

        out.append({
            "i": i,
            "pk_sha": hashlib.sha256(pk).hexdigest(),
            "ct_sha": hashlib.sha256(ct).hexdigest(),
            "ss": ss.hex(),
        })

    json.dump(out, sys.stdout, indent=0)
    dt = time.time() - t0
    print(f"\n# Python n={dim}: {rounds} Runden in {dt:.1f}s ({dt/rounds*1000:.1f} ms/Runde)",
          file=sys.stderr)


if __name__ == "__main__":
    main()
