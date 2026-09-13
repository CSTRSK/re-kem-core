#!/usr/bin/env python3
"""
Decapsulation failure probability: n=512 vs n=1024.

Runs out of the box:  python3 tools/error_probability.py

The result is the basis on which n=1024 is offered — see
docs/error-probability.md for the derivation and its limits.

HERLEITUNG (aus der Konstruktion, keine Annahme):
  keygen:  b = a*s + e
  encaps:  u = a*r + e1,  v = b*r + e2 + msg
  decaps:  w = v - u*s = msg + (e*r + e2 - e1*s)

  Rauschen = e*r + e2 - e1*s

e,r,e1,s sind iid CBD(eta). Koeffizient i von e*r summiert n Terme e_j*r_(i-j);
da die Vorzeichen der negazyklischen Faltung symmetrisch sind und Z = e*r
symmetrisch verteilt ist, ist jeder Koeffizient verteilt wie die Summe von
n iid Z. Damit:

    Rauschen ~ Summe von 2n iid Z + ein CBD(eta)-Term
    Var(Rauschen) = 2n*Var(Z) + Var(CBD) = 2n*(eta/2)^2 + eta/2

Ein Bit ist falsch, wenn |Rauschen| >= q/4.
"""
import math
from math import comb

import numpy as np

Q = 12289
ETA = 8
THRESHOLD = Q // 4
MSG_BITS = 256


def cbd_pmf(eta):
    d = {}
    for a in range(eta + 1):
        for b in range(eta + 1):
            p = comb(eta, a) * comb(eta, b) * 0.5 ** (2 * eta)
            d[a - b] = d.get(a - b, 0.0) + p
    return d


def z_pmf(eta):
    pe = cbd_pmf(eta)
    d = {}
    for e, p1 in pe.items():
        for r, p2 in pe.items():
            d[e * r] = d.get(e * r, 0.0) + p1 * p2
    return d


PZ = z_pmf(ETA)
KEYS = np.array(sorted(PZ), dtype=np.float64)
VALS = np.array([PZ[int(k)] for k in KEYS], dtype=np.float64)


def log_mgf(theta):
    z = theta * KEYS
    mx = z.max()
    return mx + math.log(float(np.sum(VALS * np.exp(z - mx))))


def chernoff_exponent(m, t):
    """min_theta  m*log M_Z(theta) - theta*t   (konvex, Gittersuche + Feinsuche)."""
    grid = np.concatenate([
        np.geomspace(1e-8, 1e-2, 200),
        np.linspace(0.01, 0.40, 400),
    ])
    best = (float("inf"), None)
    for th in grid:
        f = m * log_mgf(float(th)) - float(th) * t
        if f < best[0]:
            best = (f, float(th))
    # Feinsuche um das Minimum
    lo, hi = best[1] - 0.002, best[1] + 0.002
    for th in np.linspace(max(lo, 1e-9), hi, 400):
        f = m * log_mgf(float(th)) - float(th) * t
        if f < best[0]:
            best = (f, float(th))
    return best  # (exponent, theta*)


def safe_exp(x):
    if x > 700:
        return 1.0
    if x < -745:
        return 0.0
    return math.exp(x)


def analyse(n):
    var_cbd = ETA / 2.0
    var_z = var_cbd ** 2
    var_noise = 2 * n * var_z + var_cbd
    sd = math.sqrt(var_noise)
    sigma = THRESHOLD / sd

    m = 2 * n
    exponent, theta = chernoff_exponent(m, THRESHOLD - ETA)
    p_bit = min(2.0 * safe_exp(exponent), 1.0)
    # Bei so kleinen p_bit unterlaeuft 1-(1-p)^256 in float64 (Ausloeschung),
    # daher linearisieren: 1-(1-p)^k ~ k*p fuer p << 1/k
    p_round = MSG_BITS * p_bit if p_bit < 1e-10 else 1 - (1 - p_bit) ** MSG_BITS

    print(f"{'=' * 72}")
    print(f"  n = {n}")
    print(f"{'=' * 72}")
    print(f"  Var(Z) = (eta/2)^2                    = {var_z:.0f}")
    print(f"  Var(Rauschen) = 2*{n}*{var_z:.0f} + {var_cbd:.0f}      = {var_noise:.0f}")
    print(f"  Standardabweichung sigma              = {sd:.2f}")
    print(f"  Schwelle q/4                          = {THRESHOLD}")
    print(f"  Abstand der Schwelle in sigma         = {sigma:.2f}")
    print(f"  Chernoff: m={m} Terme, optimales theta = {theta:.6f}")
    print(f"  Chernoff-Exponent                     = {exponent:.2f}")
    print()
    print(f"  P(Bit falsch)   <= 2*exp({exponent:.1f}) = {p_bit:.3e}")
    print(f"  P(Runde falsch) <= {p_round:.3e}   ({MSG_BITS} Nachrichtenbits)")
    print(f"  entspricht 1 Fehler in {1/p_round:.2e} Runden" if p_round > 0 else "")
    return p_bit, p_round, sigma, sd, exponent


print("Rauschen = e*r + e2 - e1*s   |   Bit falsch wenn |Rauschen| >= q/4")
print()
res = {}
for n in (512, 1024):
    res[n] = analyse(n)
    print()

print("=" * 72)
print("  VERGLEICH")
print("=" * 72)
print(f"  {'n':<6}{'sigma':>8}{'Exponent':>12}{'P(Runde falsch)':>20}")
for n in (512, 1024):
    p_bit, p_round, sigma, sd, exponent = res[n]
    print(f"  {n:<6}{sigma:>8.2f}{exponent:>12.1f}{p_round:>20.3e}")

sd512, sd1024 = res[512][3], res[1024][3]
p512, p1024 = res[512][1], res[1024][1]
print()
print(f"  Streuung steigt um Faktor {sd1024/sd512:.3f}   (sqrt(2) = {math.sqrt(2):.3f})")
print(f"  Exponent verschlechtert sich um Faktor {res[1024][4]/res[512][4]:.3f}")
print(f"  P(Runde) verschlechtert sich um {p1024/p512:.2e}")
print()
print("  ABGLEICH MIT DER MESSUNG (n=512):")
print("    263.903.742 Runden, 0 Fehler  ->  beobachtet p < 3.79e-09")
print(f"    Chernoff-Schranke             ->  p <= {p512:.3e}")
print("    => Schranke liegt WEIT unter der Nachweisgrenze: kein Widerspruch.")
print("       Die Messung kann die Schranke aber nicht bestaetigen — dafuer")
print("       muesste man ~1e100 Runden fahren.")
print()
print("  KONSEQUENZ FUER n=1024:")
print(f"    Schranke {p1024:.2e} pro Runde (~2^{math.log2(p1024):.0f}).")
print("    Ein empirischer Nachweis ist prinzipiell unmoeglich — die Schranke")
print("    stuetzt sich allein auf das Rauschmodell, nicht auf die NewHope-Analyse")
print("    (die ein anderes Encoding annimmt). Genau das war der offene Punkt.")
