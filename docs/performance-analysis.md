# Performance Analysis & Extrapolation

**Source data:** four-hour soak run (`DURATION_SECONDS=14400`), 239 one-minute
samples, 75,762,512 complete KEM rounds.
**Analysis script:** reproduced below; raw results in `analysis.json`.

---

## 1. The question

Can the number of processed KEM rounds be described by a closed-form equation
in time — and is an extrapolation from four hours statistically defensible?

Define

```
N(t)  = number of completed keygen+encaps+decaps cycles after t seconds
R(t)  = instantaneous rate, measured over each 60-second window
M(t)  = resident memory (VmRSS) after t seconds
```

## 2. The equation

Least-squares fit over all 239 samples:

```
N(t) = 5253.767 · t + 41987          R² = 0.999996365132
```

The intercept is not physical: it absorbs a faster opening phase (the first
60 seconds ran at ≈5341 rounds/s, settling to ≈5260 rounds/s — a turbo/cache
effect). Discarding the first three samples as warm-up gives a cleaner
one-parameter model, the theoretically expected form (zero rounds at zero
time):

```
N(t) = 5258.15 · t                   R² = 0.999995265185
       max |relative deviation| = 1.88 %
```

Expressed per round:

```
T = 1 / r = 190.2 µs
```

## 3. Why a linear law is the right model (theory)

The per-round cost is fixed by construction — it depends only on the
parameters `(n, q, η)`, never on the secrets:

| Operation | Count per round | Cost |
|-----------|-----------------|------|
| Negacyclic NTT multiplication | 6 | O(n log n), n = 512 → 4608 butterfly steps each |
| CBD sampling (η = 8) | 5 | SHAKE-256 over ~1 KB each |
| Hash calls (SHA3-256/512, SHAKE-256) | 6 | over ~1–2 KB each |
| Serialisation | 4 | 1 KB per polynomial |

Every loop bound is a compile-time constant. There is no data-dependent
branch and no data-dependent iteration count (rejection sampling draws from
the *public* seed `seed_a`, not from secrets). Therefore the runtime of one
round is a constant `T`, and cumulatively:

```
N(t) = ∫₀ᵗ (1/T) dτ = t / T        exactly, with no higher-order terms
```

So the linear form is not merely an empirical fit — it is what the
implementation implies, and the measurement is a check on the implementation
rather than the source of the model.

## 4. Statistical verification

**Linearity.** R² = 0.9999963 over 239 points spanning 4 hours. Residuals
stay inside ±1.7 % after warm-up (RMS residual 41 550 rounds against a final
count of 75.7 M — a relative error of 0.055 %).

**Stationarity of the rate.** If the machine were drifting (thermal, memory
pressure, scheduler contention), the instantaneous rate would trend. It does
not:

| Test | Statistic | p-value | Verdict |
|------|-----------|---------|---------|
| Kendall τ | −0.0423 | 0.334 | no trend |
| Spearman ρ | −0.0751 | 0.251 | no trend |
| Linear trend β | 1.111e−03 rounds/s² | 0.546 | no trend |

Rate statistics: mean 5260.19 rounds/s, σ = 115.07, coefficient of variation
**2.19 %**, 95 % CI of the mean [5245.4, 5275.0].

**Constant memory.** Least-squares fit of `M(t)` gives a *negative* drift of
−2.36e−02 kB/s (p ≈ 0), i.e. memory is released rather than accumulated. Peak
RSS over the whole run equals the starting value (2108 kB); the process ends
at 1268 kB. A leak would show as a positive slope with growing peak — neither
occurs.

## 5. Extrapolation

With `N(t) = 5258.15 · t`:

| Duration | Rounds |
|----------|--------|
| 1 hour | 18,929,338 |
| 1 day | 454,304,119 |
| 1 week | 3,180,128,832 |
| 1 month (30 d) | 13,629,123,566 |
| 1 year (365 d) | 165,821,003,388 |

Inverse, `t(N) = N / r`:

| Target | Duration |
|--------|----------|
| 10⁹ rounds | 52.8 h |
| 10¹¹ rounds | 5,282.8 h (≈220 days) |
| 10¹² rounds | 52,828 h (≈6.0 years) |

## 6. Confidence interval of the slope

From the two-parameter fit (all points):

```
r = 5253.767 rounds/s   95 % CI [5252.485, 5255.049]
⇒ relative uncertainty ±0.0244 %
T = 190.34 µs/round     95 % CI [190.30, 190.40]
```

## 7. What this does and does not prove

**Does prove (for this machine, this build):**

- The throughput law is linear with R² > 0.99999; there is no detectable
  degradation over four hours of continuous load.
- The rate is stationary under three independent trend tests.
- Memory is O(1); no leak.
- 75.7 M rounds executed with zero failures and 18,497 implicit-rejection
  checks all behaving correctly.

**Does not prove:**

- Extrapolation beyond the measured window assumes the machine keeps behaving
  identically. Thermal state, co-tenancy and CPU frequency policy can change
  over days; the 1-year figure is arithmetic, not a measurement.
- Linear time says nothing about *constant time in the side-channel sense*.
  A routine can be linear in `t` and still leak through timing that depends on
  secrets. That question is addressed separately by the dudect-style analysis
  in the README (|t| < 1 over 100,000 measurements), which is itself a
  statistical negative result rather than a proof.
- These numbers are single-machine, from a 2-core VPS.

## 8. Reproducing

```bash
DURATION_SECONDS=14400 cargo run --release --example soak 2> soak.log
python3 tools/analyze_soak.py soak.log
```

`tools/analyze_soak.py` performs the fits, the trend tests, the residual
analysis and the extrapolation, and writes `analysis.json`.
