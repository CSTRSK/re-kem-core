#!/usr/bin/env python3
"""
Soak-run analysis: fits the throughput law, tests stationarity, checks for
memory leaks and extrapolates.

Input: the stderr log produced by
    DURATION_SECONDS=14400 cargo run --release --example soak 2> soak.log

Usage:
    python3 tools/analyze_soak.py soak.log [--json out.json]

Outputs the fitted equation N(t) = r*t + b, the R^2, the 95 % CI of the slope,
three trend tests on the instantaneous rate, the memory drift, and an
extrapolation table.
"""
import argparse
import json
import re
import sys

import numpy as np
import scipy.stats as st

LINE = re.compile(
    r"\[\s*([\d.]+)s\]\s+(\d+) Runden\s+\|\s+(\d+)/s \(Ø\s+(\d+)/s\)"
    r".*RSS (\d+) kB"
)

#: Samples to discard as warm-up (the opening seconds run faster).
WARMUP = 3


def parse(path):
    t, n, rate, rss = [], [], [], []
    for line in open(path, encoding="utf-8"):
        m = LINE.search(line)
        if m:
            t.append(float(m.group(1)))
            n.append(int(m.group(2)))
            rate.append(float(m.group(3)))
            rss.append(float(m.group(5)))
    if not t:
        sys.exit("no samples found -- is this an `example soak` log?")
    return (np.array(t), np.array(n, dtype=float), np.array(rate), np.array(rss, dtype=float))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--json", default=None, help="write results as JSON")
    args = ap.parse_args()

    t, n, rate, rss = parse(args.log)
    print(f"Messpunkte: {len(t)}   Zeitraum: {t.min():.0f}..{t.max():.0f}s "
          f"({(t.max()-t.min())/3600:.2f} h)")
    print(f"Runden:     {n[0]:,.0f} .. {n[-1]:,.0f}\n")

    # ── model A: two-parameter line ──
    a = st.linregress(t, n)
    print("MODELL A   N(t) = r*t + b")
    print(f"  r      = {a.slope:.4f} Runden/s")
    print(f"  b      = {a.intercept:,.1f} Runden")
    print(f"  R^2    = {a.rvalue**2:.12f}")
    tcrit = st.t.ppf(0.975, len(t) - 2)
    lo, hi = a.slope - tcrit * a.stderr, a.slope + tcrit * a.stderr
    print(f"  95% CI = [{lo:.4f}, {hi:.4f}]  (±{tcrit*a.stderr/a.slope*100:.4f} %)\n")

    # ── model B: one-parameter line through the origin, after warm-up ──
    tc, nc, rc, mc = t[WARMUP:], n[WARMUP:], rate[WARMUP:], rss[WARMUP:]
    r0 = float((tc * nc).sum() / (tc * tc).sum())
    pred = r0 * tc
    resid = nc - pred
    rel = np.abs(resid / nc) * 100
    ss_tot = ((nc - nc.mean()) ** 2).sum()
    r2 = 1 - (resid**2).sum() / ss_tot
    print(f"MODELL B   N(t) = r*t   (Ohne die ersten {WARMUP} Samples)")
    print(f"  r      = {r0:.4f} Runden/s")
    print(f"  T      = {1/r0*1000:.4f} ms pro Runde")
    print(f"  R^2    = {r2:.12f}")
    print(f"  max|rel. Abw.| = {rel.max():.4f} %")
    print(f"  RMS Residuum   = {np.sqrt((resid**2).mean()):,.1f} Runden\n")

    # ── stationarity of the instantaneous rate ──
    kt = st.kendalltau(tc, rc)
    sp = st.spearmanr(tc, rc)
    lin = st.linregress(tc, rc)
    print("STATIONARITÄT der Momentanrate")
    print(f"  Kendall  tau = {kt.statistic:>8.4f}  p = {kt.pvalue:.4f}")
    print(f"  Spearman rho = {sp.statistic:>8.4f}  p = {sp.pvalue:.4f}")
    print(f"  Trend    beta= {lin.slope:.3e}  p = {lin.pvalue:.4f}")
    trend = (kt.pvalue < 0.05) or (sp.pvalue < 0.05) or (lin.pvalue < 0.05)
    print(f"  => {'TREND SIGNIFIKANT' if trend else 'kein Trend — stationär'}")
    print(f"  Mittel = {rc.mean():.2f} ± {rc.std(ddof=1):.2f} Runden/s "
          f"(CV {rc.std(ddof=1)/rc.mean()*100:.3f} %)\n")

    # ── memory ──
    mr = st.linregress(tc, mc)
    print("SPEICHER   M(t) = M0 + gamma*t")
    print(f"  Start/Ende = {mc[0]:,.0f} / {mc[-1]:,.0f} kB   Peak {mc.max():,.0f} kB")
    print(f"  Drift gamma= {mr.slope:.3e} kB/s   (p = {mr.pvalue:.4f})")
    print(f"  über 4 h   = {mr.slope*14400:,.1f} kB\n")

    # ── extrapolation ──
    print(f"EXTRAPOLATION   N(t) = {r0:.4f} * t")
    ext = {}
    for label, secs in [("1 Stunde", 3600), ("1 Tag", 86400), ("1 Woche", 604800),
                        ("1 Monat", 2592000), ("1 Jahr", 31536000)]:
        ext[label] = int(r0 * secs)
        print(f"  {label:<12}{r0*secs:>22,.0f} Runden")
    print()
    for target in (10**9, 10**11, 10**12):
        print(f"  {target:>16,} Runden = {target/r0/3600:>12,.1f} h")

    if args.json:
        json.dump(
            {
                "samples": len(t),
                "rounds": int(n[-1]),
                "modelA": {"equation": f"N(t) = {a.slope:.6f}*t + {a.intercept:.3f}",
                           "r": round(a.slope, 6), "r2": round(a.rvalue**2, 12),
                           "ci95": [round(lo, 6), round(hi, 6)]},
                "modelB": {"equation": f"N(t) = {r0:.6f}*t", "r": round(r0, 6),
                           "per_round_ms": round(1/r0*1000, 6), "r2": round(r2, 12),
                           "max_rel_deviation_percent": round(float(rel.max()), 6),
                           "rms_residual_rounds": round(float(np.sqrt((resid**2).mean())), 1)},
                "stationary": not trend,
                "kendall": {"tau": round(float(kt.statistic), 4), "p": round(float(kt.pvalue), 4)},
                "rate": {"mean": round(float(rc.mean()), 2), "std": round(float(rc.std(ddof=1)), 2),
                         "cv_percent": round(float(rc.std(ddof=1)/rc.mean()*100), 3)},
                "memory": {"start_kb": int(mc[0]), "end_kb": int(mc[-1]),
                           "peak_kb": int(mc.max()), "drift_kb_per_s": float(mr.slope)},
                "extrapolation_rounds": ext,
            },
            open(args.json, "w"), indent=2,
        )
        print(f"\n→ {args.json}")


if __name__ == "__main__":
    main()
