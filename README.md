<div align="center">

# 🦀 re-kem-core

**Constant-Time Montgomery Field Arithmetic for RE-KEM (Ring-LWE, q = 12289)**

![Rust](https://img.shields.io/badge/Rust-1.98-orange?logo=rust)
![License](https://img.shields.io/badge/License-AGPL--3.0-blue)
![Tests](https://img.shields.io/badge/tests-5%2F5-green)

The Rust core for the post-quantum [RE-KEM](https://github.com/CSTRSK/RE-KEM) port —
the piece the pure-Python reference implementation explicitly cannot provide:
**real control over timing and memory-access patterns**.

</div>

---

## Why this crate exists

The Python reference (`rekem.py`) states it plainly in its own docstrings:

> *"Constant-time" is here an algorithm-level design goal, not a verified property
> of the execution. […] A production deployment needs a port to a language with
> real control over timing/memory-access patterns, plus measurement (e.g. dudect),
> before the constant-time claim is defensible.*

This crate is that port's foundation: arithmetic on `Z_q` with **no secret-dependent
branches**, built for the NewHope-512 parameter regime used by RE-KEM.

## What is implemented

| Module | Contents |
|--------|----------|
| `field.rs` | `FieldElement` — Montgomery-form arithmetic mod q = 12289 |

Operations (all branchless):
- `from_plain` / `to_plain` — Montgomery conversion
- `mul` — Montgomery multiplication (REDC)
- `add` / `sub` — conditional-subtraction reduction, no data-dependent branches

### `no_std`

The crate is `#![no_std]` (only `core` + the `subtle` crate) — it can therefore be
compiled for embedded and bare-metal targets where no Rust standard library exists.
`cargo test` links `std` so the test suite can use `Vec`.

## 🐛 The R-constant bug this crate caught

A reviewed draft of the Rust port stated:

```text
R = 2^16 ≡ 4095 (mod q)     ← WRONG
```

The correct value is **4091**:

```text
2^16 mod 12289 = 4091        (verified: pow(2,16,12289) == 4091)
```

**Why it matters:** `from_plain(a) = a · R² · R⁻¹ = a·R mod q`. With a wrong `R²`,
*every* field element is silently mis-scaled. `keygen`/`encaps`/`decaps` would run
without crashing and only fail statistically — or not at all. Not a side-channel bug:
a correctness bug, and a far nastier one to catch. The test
`r_mod_q_constant_is_4091_not_4095` pins it down.

All three Montgomery constants are verified independently in the test suite:

| Constant | Value | Verification |
|----------|-------|--------------|
| `R mod q` | 4091 | `2^16 mod 12289` |
| `-q⁻¹ mod R` | 12287 | `65536 - pow(12289,-1,65536)` |
| `R² mod q` | 10952 | `pow(65536, 2, 12289)` |

## Usage

```rust
use re_kem_core::FieldElement;

let a = FieldElement::from_plain(1234);
let b = FieldElement::from_plain(5678);

let product = a.mul(b).to_plain();   // == (1234 * 5678) % 12289
let sum     = a.add(b).to_plain();
let diff    = a.sub(b).to_plain();
```

## Build & test

```bash
cargo build --release
cargo test
```

```
running 5 tests
test field::tests::addition_and_subtraction_match_naive ... ok
test field::tests::multiplication_matches_naive_mod_mul ... ok
test field::tests::r2_mod_q_constant_is_correct ... ok
test field::tests::r_mod_q_constant_is_4091_not_4095 ... ok
test field::tests::roundtrip_plain_montgomery_plain ... ok
test result: ok. 5 passed; 0 failed
```

## Cross-validation against the Python reference

`examples/cross_vectors.rs` emits deterministic test vectors; `tools/cross_check.py`
recomputes them with the Python reference and compares. This proves that the Rust
port and the Python implementation agree on every operation.

```bash
# Rust side → vectors.json
cargo run --release --example cross_vectors > /tmp/vectors.json

# Python side → compare
python3 tools/cross_check.py /tmp/vectors.json
```

## Status / Roadmap

Implemented: constant-time field arithmetic.

Still required for a complete KEM (matching `rekem.py`):
- [ ] Negacyclic NTT (O(n log n) polynomial multiplication)
- [ ] CBD sampling (η = 8)
- [ ] Rejection sampling for a(x)
- [ ] Polynomial packing / serialisation
- [ ] `keygen` / `encaps` / `decaps` (Fujisaki–Okamoto)
- [ ] Timing validation with `dudect`
- [ ] Intermediate drop-through checks

## Security disclaimer

Educational / research reference. **Not audited, not production-ready.** The
branchless structure is a design property of the algorithm; a formal constant-time
guarantee still requires dudect-style measurement on the target platform.

## Related

- [RE-KEM](https://github.com/CSTRSK/RE-KEM) — Python reference implementation (NewHope-512)
- Live: [cstrsk.de](https://cstrsk.de)

---

**CSTRSK.DE · COPYRIGHT 2008–2026**
