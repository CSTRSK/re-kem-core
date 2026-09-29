# Kani-Beweise für RE-KEM (`re-kem-core`)

Formale Prüfung der Arithmetik des Rust-Ports von RE-KEM
(Ring-LWE, n = 512, q = 12289, Montgomery R = 2^16) mit Kani 0.68.

Arbeitskopie: dieses Verzeichnis. Am Original (`/root/rekem-repro`) wurde
nichts geändert. Die einzige Änderung hier ist die **Sichtbarkeit** von
`montgomery_reduce` und `montgomery_mul_raw` (`fn` → `pub(crate)`), damit die
Beweise sie aufrufen können — Semantik unverändert.

## Ergebnis

| # | Beweis | Aussage | Ergebnis | Zeit |
|---|---|---|---|---|
| 1 | `verify_ct_reduce_once` | Für **alle** a ∈ [0, 2q): Ergebnis < q und restgleich zu a | **SUCCESSFUL** | 0,06 s |
| 2 | `verify_montgomery_reduce` | Für **alle** t < q·R: kein u32-Überlauf, t + m·q durch R teilbar, Ergebnis < q, **r·R ≡ t (mod q)** | **SUCCESSFUL** | 464 s |
| 3 | `verify_from_plain_to_plain_roundtrip` | Für alle a < q: `to_plain(from_plain(a)) == a` | **SUCCESSFUL** | 2,3 s |
| 4 | `verify_constants` | `R mod q = 4091` (nicht 4095), `R² = 10952`, `q⁻¹ mod R = 53249`, `one()`/`zero()` korrekt | **SUCCESSFUL** | 0,3 s |
| 5 | `verify_bit_reversal_index_safe` | Die Bit-Umkehr läuft nie aus dem Array (j < N), die Schleife endet | **SUCCESSFUL** | 0,1 s |
| 6 | `verify_butterfly_bounds` | Schmetterling: kein Überlauf, Summe/Differenz < 2q, nach der Reduktion < q | **SUCCESSFUL** | 0,4 s |
| 7 | `verify_ntt_context_tables_in_range` | `NttContext::new()` läuft ohne Panik durch, ψ < q | **SUCCESSFUL** | 47 s |
| 8 | `verify_multiplication_correct_modular` | Für alle a, b < q: Montgomery-Produkt == a·b mod q — modular mit Reduktions-Stub | **Zeitlimit 900 s gerissen** ✗ | — |
| 9 | `verify_add_sub_correct_modular` | add/sub gegen die gewöhnliche Modulo-Rechnung, modular | **Zeitlimit 900 s gerissen** ✗ | — |
| 10 | `verify_multiplication_bounded_8bit` | Multiplikation für **alle a, b < 256**, modular | **SUCCESSFUL** (22 Prüfungen) | 27,8 s |
| 11 | `verify_add_sub_bounded_8bit` | add/sub für alle a, b < 256, ohne Stubs | **SUCCESSFUL** (17 Prüfungen) | 15,2 s |

## Der eigentliche Engpass: nichtlineare Arithmetik mod q

Auch nach dem Umbau auf Stubs rissen Beweis 8 und 9 das 900-Sekunden-Limit. Die
Ursache liegt **nicht** in der Implementierung, sondern in der Spezifikation,
die der Solver prüfen muss: der Stub verlangt `(r · R) mod q == t mod q` mit
**symbolischem** r — das ist eine nichtlineare Kongruenz (Multiplikation zweier
unbekannter 16-Bit-Werte modulo einer Primzahl). Für den SAT-Kern ist das der
teure Teil; die Anzahl der Reduktionsschritte spielt kaum noch eine Rolle.

Genau deshalb funktionieren die eingeschränkten Fassungen: mit a, b < 256
schrumpft der Suchraum, und beide Aussagen sind in 15–28 Sekunden vollständig
bewiesen (Beweise 10 und 11) — für diese Domäne, nicht für ganz q.

## Warum zwei Beweise „modular" sind

Die direkte Fassung von Beweis 8 (Multiplikation mit symbolischem a **und** b)
lief in ein 900-Sekunden-Zeitlimit: **eine** symbolische Montgomery-Reduktion
kostet den Solver schon 464 Sekunden, die Multiplikation ruft sie zweimal auf,
und der Verifizierer rechnet zusätzlich über 32-Bit-Zwischenwerte.

Deshalb derselbe Satz in zwei Schritten:

1. **Beweis 2** zeigt die Reduktion vollständig (ohne Annahmen).
2. Beweis 8/9 ersetzen die Reduktion durch einen Stub, der **nur** die in
   Beweis 2 bewiesene Spezifikation erfüllt (`r < q` und `r·R ≡ t (mod q)`),
   und beweisen dann die Komposition.

Das ist eine echte Aussage über den Code — vorausgesetzt, die bewiesene
Spezifikation wird angewandt. Eine Einschränkung gehört dazu: der Stub setzt
`t = a·b < q·R` voraus; für a, b < q gilt `a·b < q² < q·R` ✓.

Aufruf: `cargo kani -Z stubbing --harness <name>`

## Ausführen

```bash
cargo kani --harness verify_ct_reduce_once
cargo kani --harness verify_montgomery_reduce          # ~8 Minuten
cargo kani --harness verify_from_plain_to_plain_roundtrip
cargo kani --harness verify_constants
cargo kani --harness verify_bit_reversal_index_safe
cargo kani --harness verify_butterfly_bounds
cargo kani --harness verify_ntt_context_tables_in_range
cargo kani -Z stubbing --harness verify_multiplication_correct_modular
cargo kani -Z stubbing --harness verify_add_sub_correct_modular
```

## Rohausgaben

Die vollständigen Läufe liegen unter `verification/`:

| Datei | Inhalt |
|---|---|
| `kani-lauf-1-hauptlauf.log` | die sieben Beweise der vollen Domäne, dazu die Gegenproben (Tabellenlänge, Barrett-Überlauf) |
| `kani-lauf-3-modular-zeitlimit.log` | die modularen Fassungen von Multiplikation und add/sub: Zeitlimit |
| `kani-lauf-4-8bit-domane.log` | die eingeschränkte Domäne a, b < 256: beide erfolgreich |

## Was hier nicht bewiesen wird

* **Die NTT-Multiplikation gegen das Schulbuchverfahren über alle 512
  Koeffizienten.** Das sind 512 symbolische Eingaben plus 9 Schichten — für
  CBMC außerhalb jeder Reichweite. Dafür steht der Laufzeittest
  `ntt::tests::ntt_multiplication_matches_naive`.
* **Konstantzeit.** Kani prüft Wertebereiche, Überläufe und Indizes, nicht
  Timing. Die Zweigfreiheit ist im Code dokumentiert und gehört mit einem
  Laufzeitverfahren (dudect/Timing-Messung) geprüft, nicht mit einem
  Beweiser.
* **Die KEM-Stufe selbst** (FO-Transformation, Hashing, Envelope). Dort ist
  Kani nicht das richtige Werkzeug; das deckt die Byte-Gleichheit gegen die
  Python-Referenz ab.

## Ein Fehler in diesem Prüfprojekt (zur Nachvollziehbarkeit)

Der erste Lauf von Beweis 4 schlug fehl — die Prüfung lautete
`(12287 + 53249) mod q == 0`, was die Aussage „−q⁻¹ mod R" mit „mod q"
verwechselt. Der Code war richtig, die Prüfung falsch. Korrekt ist
`(12287 · q) mod 2^16 == 2^16 − 1`. Nach der Korrektur: SUCCESSFUL.
