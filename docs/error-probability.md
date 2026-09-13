# Decapsulation failure probability — this crate's encoding, both dimensions

Why this document exists: `n = 1024` is offered by this crate. The published
NewHope-1024 analysis does **not** cover it, because that work assumes a
**4-fold redundant per-bit encoding**, whereas this implementation uses
**zero padding** — the 256 message bits occupy the first 256 coefficients at
amplitude `q/2` and coefficients 256…n−1 stay 0. Different encoding, different
noise accumulation, therefore a different failure probability that has to be
derived rather than inherited.

Reproduce with:

```bash
python3 tools/error_probability.py
```

## 1. Where the noise comes from

Not assumed — read off the scheme:

```
keygen:  b = a·s + e
encaps:  u = a·r + e1,   v = b·r + e2 + msg
decaps:  w = v − u·s
           = (a·s + e)·r + e2 + msg − (a·r + e1)·s
           = msg + (e·r + e2 − e1·s)
                   └────── noise ──────┘
```

A bit is decoded wrongly when `|noise| ≥ q/4` (the message sits at 0 or `q/2`).

## 2. Distribution of one noise coefficient

`e`, `r`, `e1`, `s` are independently CBD(η)-distributed with η = 8.
Coefficient `i` of `e·r` sums `n` terms `e_j · r_(i−j)`. The negacyclic sign
pattern is symmetric and `Z := e·r` is symmetrically distributed, so **every**
coefficient of `e·r` is distributed as a sum of `n` iid copies of `Z`.
The same holds for `e1·s`. `e2` contributes a single CBD coefficient.
Hence:

```
noise  ~  (sum of 2n iid Z)  +  CBD(η)
```

with, using `Var(CBD(η)) = η/2` and `E[Z] = 0`:

```
Var(Z)     = (η/2)² = 16
Var(noise) = 2n·16 + 4
```

## 3. Bound

`Z` has a small finite support (±64), so its moment-generating function is an
exact finite sum and Chernoff's bound can be evaluated numerically without
approximation:

```
P(sum ≥ t)  ≤  exp( min_θ [ m·log M_Z(θ) − θ·t ] ),    m = 2n
```

With `t = q/4 − η = 3072 − 8` (the CBD term is bounded by η, so it is absorbed
conservatively) and doubling for the two-sided event:

```
P(bit wrong)  ≤  2 · exp( min_θ [ 2n·log M_Z(θ) − θ·3064 ] )
P(round wrong) ≤ 256 · P(bit wrong)     (256 message bits, union bound)
```

## 4. Result

| n | σ(noise) | σ-distance to q/4 | Chernoff exponent | P(round wrong) |
|---|----------|-------------------|-------------------|----------------|
| **512** | 128.02 | **24.00** | −242.2 | **3.24e−103** |
| **1024** | 181.03 | **16.97** | −135.7 | **5.96e−57 (≈ 2⁻¹⁸⁷)** |

Two sanity checks fall out:

- The noise standard deviation grows by **exactly √2** (128.02 → 181.03,
  ratio 1.4142) — what the model predicts when the convolution length doubles.
  The measurement agrees with the model, which is the closest thing to a
  validation the model can get.
- For n = 512 the bound (3.2e−103) is consistent with the observed 263,903,742
  failure-free rounds: the observation only rules out rates above ≈3.8e−9, so
  there is no contradiction — but equally, the observation does not confirm the
  bound.

**Conclusion: `n = 1024` with this encoding is safe.** 2⁻¹⁸⁷ is far below the
usual 2⁻¹²⁸ bar for KEM failure probability. The cost of the larger dimension
is 1.8e+46 in failure probability — irrelevant in absolute terms, but the
reason the number is stated rather than waved through.

## 5. What this document does *not* claim

**5.1 It cannot be confirmed empirically.** To see one failure at 5.96e−57 you
would need ~1e56 rounds. At the measured 0.39 ms/round that is ~1e47 years.
The 263.9 M rounds run for n = 512 are **not** evidence for this bound; they
are evidence that nothing is grossly broken. The guarantee rests on the model
in §2, not on measurement. Anyone who says "we ran it for a long time" has not
shown 2⁻¹⁸⁷ — they have shown nothing above their sample limit.

**5.2 The bound is an upper bound, not the true probability.** Chernoff is
tight in the exponent but not exact. The true failure probability is smaller;
the number above is what can be *argued*.

**5.3 The model assumes independent, correctly distributed noise.** It follows
from the construction and is confirmed by the cross-validation against the
Python reference (bit-identical at both dimensions), but a flaw in the sampler
that the reference shares would be invisible to both. The sampler's properties
are checked separately (`expand_a_rejection_sampling_yields_uniform_range`,
`cbd_values_within_eta_range`).

**5.4 Nothing here is a security estimate.** A larger `n` raises the lattice
security estimate; this document is only about *correctness* under noise. The
security of a parameter set is a separate question with separate literature.

**5.5 Only these two dimensions are covered.** The derivation is per dimension
because `Var(noise) = 2n·Var(Z) + Var(CBD)` depends on `n`. A third set needs
its own line in the table above.
