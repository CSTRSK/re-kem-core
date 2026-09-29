# Härtungs-Harnesses für `re-kem-core`

Vier automatisierte Prüfungen: Constant-Time-Audit (Valgrind), Differential-Fuzzing
(cargo-fuzz/libFuzzer), IND-CCA2 mit Implicit Rejection, und Fault-Injection in der
Entkapselung. Alle laufen über **einen** Einstieg mit sauberem Exitcode:

```bash
FUZZ_SEKUNDEN=60 bash scripts/run_harnesses.sh     # 0 = grün, >0 = Befund
```

| # | Harness | Datei | Werkzeug |
|---|---|---|---|
| 1 | Constant-Time-Audit (ct-grind) | `tests/ct_valgrind.rs`, `tests/ct_control.rs`, `tests/common/vg.rs` | Valgrind/Memcheck |
| 2 | Differential-Fuzzing NTT ↔ naive Faltung | `fuzz/fuzz_targets/ntt_algebra.rs` | cargo-fuzz (libFuzzer + ASan) |
| 3 | IND-CCA2 und Implicit Rejection | `tests/ind_cca2.rs` | cargo test |
| 4 | Fault-Injection (äußere und innere Störung) | `tests/fia.rs`, `src/fia.rs` (Feature `fia-hooks`) | cargo test |

Voraussetzungen: `dnf install valgrind valgrind-devel gcc-c++`, `cargo install cargo-fuzz`,
`rustup toolchain install nightly`.

## Wichtig zum Parametersatz

Der Auftrag nennt **q = 3329, n = 256** — das ist der Parametersatz von Kyber/FIPS 203
und **nicht** der dieses Crates: `params::ACTIVE` ist `NEWHOPE_512` mit **q = 12289, n = 512**.
Der Unterschied ist nicht kosmetisch: für q = 3329 ist q − 1 = 3328 = 13 · 256, aber
**512 ∤ 3328**, es gibt also keine 512-te Einheitswurzel. Kyber löst das mit einer
*unvollständigen* NTT (7 statt 8 Schichten) auf Basis von Barrett/Montgomery-Arithmetik
in `i16` — ein anderer Rechenkern, nicht derselbe mit anderen Zahlen.

Deshalb sind die Harnesses **parameterneutral** geschrieben: sie lesen `N`, `Q`, `POLY_LEN`
aus dem Crate. Läuft `ACTIVE` gegen q = 3329/n = 256, laufen sie unverändert mit — nur
prüfen sie dann andere Mathematik. Der i16-Barrett/Montgomery-Kern für 3329/256 liegt
separat in `/root/invntt-kani` (inkl. Kani-Beweisen und drei belegten Defekten).

## Ergebnisse der Läufe (28./29.09.2026, x86-64, 2 vCPU)

| Harness | Ergebnis |
|---|---|
| 1 Constant-Time-Audit | **0 Fehler, 0 Kontexte** unter `valgrind --error-exitcode=99` |
| 1 Positivkontrolle | **2 Meldungen** — der Detektor greift (siehe unten) |
| 2 Fuzzing, 121 s | **72.406 Läufe**, 598 exec/s, 279 neue Korpus-Einträge, Abdeckung 89/221, **keine Abweichung** |
| 3 IND-CCA2 | 7/7 Tests grün (200 Bitfehler-Stichproben, 2048 v-Positionen, Zufalls-Chiffretexte, manipulierter sk) |
| 4 FIA äußere Störung | 256 sk-Fehler: 253 in der Ablehnung, 3 ohne Wirkung; 2048 ct-Positionen: **2048 verschiedene Ablehnungs-Secrets** |
| 4 FIA innere Störung | 512 Zwischenvektor-Fehler: 442 ohne Wirkung, **70 in der Ablehnung**, **genau 2 verschiedene Secrets** |

Die letzte Zeile ist die wichtigste Aussage der FIA-Suite: der Chiffretext bleibt bei
einer inneren Störung unverändert, das Ablehnungs-Secret hängt also nur an `z` und `h(ct)`.
Dass **alle** wirksamen Störungen dasselbe Secret ergeben und es genau zwei Ergebnisse gibt,
zeigt: es existiert kein dritter Ausgabepfad, über den Teilinformationen entweichen könnten.

## Befunde

### Befund 1 — `debug_assert!` in `FieldElement::from_plain` war über angreifbare Daten erreichbar **(behoben)**

`decode_poly` ruft `FieldElement::from_plain(v)` mit dem rohen 16-Bit-Wert aus den
Chiffretext-Bytes. In Debug-Builds (und genau so baut libFuzzer) greift die Zusicherung
`(a as u32) < Q` und der Prozess bricht ab. Der Fuzzing-Lauf hat das **sofort** gefunden:

```
thread panicked at src/field.rs:101: assertion failed: (a as u32) < Q
SUMMARY: libFuzzer: deadly signal
Artefakt: fuzz/artifacts/ntt_algebra/crash-ab00ec3e… (4096 B)
```

Im Release-Build (ohne `debug_assertions`) läuft derselbe Fall durch und wird still
reduziert — der Test `ind04_koeffizienten_ueber_q` hält beide Verhalten fest.

**Behoben (29.09.2026).** `decode_poly` reicht keine Rohwerte mehr durch: jeder
16-Bit-Wert wird zweigfrei und explizit nach [0, q) reduziert
(`field::reduziere_kanonisch`, ⌈65536/q⌉ bedingte Subtraktionen mit Maske).
Zusätzlich ist `FieldElement::from_plain` selbst total — die Zusicherung ist weg,
die Funktion reduziert intern. Ergebnis: Debug- und Release-Build haben dieselbe
Semantik (`from_plain(v) == v mod q`), und **kein** Eingabewert kann paniken.

Belegt durch `tests/decode_untrusted.rs`: erschöpfend über alle 65.536 Rohwerte,
plus der frühere Absturzfall (Chiffretext aus lauter 0xFF) und Zufallspuffer —
ausgeführt im **Debug-Profil**, also genau dort, wo die Zusicherung früher zuschlug.
Der Harness-Einstieg fährt diesen Test als Schritt 0 mit
`cargo test` (Debug) und nicht im Release-Profil.

### Befund 2 — der Audit muss seine eigene Vergiftung richtig wählen

Der erste Lauf meldete **3213 Fehler aus 7 Kontexten**. Nach den Stapelspuren waren es
zwei Klassen, beide **keine Lecks in der Bibliothek**:

* `sampling::expand_a` — die Verwerfungsschleife verzweigt auf Bytes, die aus `seed_a`
  stammen. `seed_a` erzeugt die *öffentliche* Matrix A; dass dort verzweigt wird, ist
  korrekt und gewollt. Wer den Seed vergiftet, misst einen Fehlalarm.
* Vergleiche **im Testcode** selbst (`assert_eq!` auf vergifteten Polynomen).

Nach der Korrektur des Modells — vergiftet werden nur Rauschsaat, `z`, Nachricht und die
geheimen Anteile von `sk`; vor jedem Vergleich wird der Speicher wieder als bekannt
markiert — bleiben **0 Fehler**. Beide Regeln stehen als Kommentar im Testkopf, damit
der nächste Bearbeiter sie nicht wieder verletzt.

### Befund 3 — die Positivkontrolle deckt nur eine Leckform ab

`tests/ct_control.rs` enthält drei absichtliche Lecks. Gemeldet werden die beiden
**Speicherzugriffs**-Formen (Index auf Geheimnis, Produkt als Index). Der reine
**Sprung**-Kontrolltest wird nicht gemeldet, weil LLVM die Verzweigung in reine
Arithmetik auflöst — für die Bibliothek das gewünschte Ergebnis, für die Kontrolle
aber eine Lücke: die Empfindlichkeit des Audits für die *Sprung*-Form ist mit diesem
Muster nicht belegt. Wer sie belegen will, braucht einen Zweig, den der Optimierer
nicht entfernen kann (etwa einen Aufruf, den er nicht einordnen kann).

## Grenzen

* Valgrind prüft **Datenabhängigkeit**, nicht Zeit: ein Leck durch Cache-Verhalten oder
  Sprungvorhersage ist damit nicht nachweisbar. Dafür braucht es Messungen am Silizium
  (dudect, Zähler, Statistik) — Kani ist für Timing ebenso wenig das Werkzeug.
* Die Fuzzing-Aussage gilt für die **geprüfte Rechenzeit und Eingabeklasse**, nicht als
  Beweis. Sie ist die schnelle Gegenprobe zum Beweis, nicht dessen Ersatz.
* Die innere Störung (Harness 4b) ist **software-emuliert**: ein Bit in einem
  Zwischenvektor, keine physikalische Injektion mit Zeitbezug. Der Haken ist per Feature
  `fia-hooks` abgeschaltet, wenn das Crate normal gebaut wird.
* `tests/../src/fia.rs` und die zwei `pub(crate)`-Zugriffe in `field.rs` (`roh`,
  `setze_roh`) sind ausschließlich für die Tests da. Das ausgelieferte Verhalten ist
  unverändert; im Normalbau kompiliert das Modul nicht mit.
