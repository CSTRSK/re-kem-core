# Abschlussbericht: Hybride KEMs

Stand 11.11.2026. Branch `feature/hybrid-kems`, Basis `372a5c7`.

## Ergebnis der Prüfkommandos

Alle Läufe auf diesem Rechner (4 vCPU, x86-64), vollständige `test result`-Zeilen
in `/tmp/abnahme.log`. Auszug der Hybrid-Suite:

| Kommando | Ergebnis |
|---|---|
| `cargo test --no-fail-fast` | alle Suites `0 failed` |
| `cargo test --release --no-fail-fast` | alle Suites `0 failed` |
| `cargo test --features hybrid-rekem-x25519 --no-fail-fast` | `15 passed; 0 failed` |
| `cargo test --release --features hybrid-rekem-x25519 --no-fail-fast` | `15 passed; 0 failed` |
| `cargo test --features hybrid-mlkem-x25519 --no-fail-fast` | `16 passed; 0 failed` |
| `cargo test --release --features hybrid-mlkem-x25519 --no-fail-fast` | `16 passed; 0 failed` |
| `cargo test --release --all-features --no-fail-fast` | `29 passed; 0 failed` (Hybrid-Suite) |
| `cargo build --no-default-features` | `Finished` |
| `cargo build --no-default-features --features hybrid-rekem-x25519` | `Finished` |
| `cargo clippy --all-features -- -D warnings` | **nicht gelaufen** — `cargo-clippy` ist für die Toolchain nicht installiert |

Basislinie vor der Arbeit: 87 Tests grün (31 lib + 3 ct_control + 6 ct_valgrind
+ 5 decode_untrusted + 26 eigenschaften + 3 fia + 7 ind_cca2 + 5 kat + 1 doc).
Nach der Arbeit unverändert.

## Mutationsprobe: 5 von 5 erkannt

| # | Mutation | erkannt durch |
|---|---|---|
| 1 | `x_ct` im Kombinierer weggelassen | 3 Tests |
| 2 | `pq_ss` und `x_ss` vertauscht | 1 Test |
| 3 | `x_pk` im sk als Nullen abgelegt | 3 Tests |
| 4 | Null-Prüfung in `encaps` entfernt | 1 Test |
| 5 | `algorithm_id` im Kombinierer ignoriert | 1 Test |

Nach jeder Mutation `cp` der Originaldatei; `diff -q` bestätigt am Ende
Identität.

## Verwendete Crates

| Crate | Version | Lizenz | Zweck |
|---|---|---|---|
| `x25519-dalek` | 2.0.1 | BSD-3-Clause | X25519 (RFC 7748) |
| `ml-kem` | 0.3.4 | Apache-2.0 OR MIT | ML-KEM-768 (FIPS 203) |

Beide sind mit AGPL-3.0 verträglich. `x25519-dalek` 3.0.0 existiert, wurde aber
nicht genommen: Die Anleitung nennt 2.x, und 2.0.1 ist nicht yanked.

## Annahmen und Abweichungen

**1. `is_offered()` war inkonsistent.** Im Ausgangszustand stand
`HybridReKem512X25519` bereits in der `matches!`-Liste, obwohl es keinen Adapter
gab — `Envelope::decode_supported` hätte das Format akzeptiert, die Registry
hätte `None` geliefert. Das ist jetzt feature-abhängig über `cfg!()`, sodass
`is_offered()` und `Registry::get()` immer übereinstimmen. Der Test
`reserved_algorithm_parses_but_is_not_offered` bleibt unverändert gültig, weil er
nur `MlKem768` prüft. Ein neuer Test `hyb13_registry_ohne_feature_nicht_registriert`
prüft die Übereinstimmung für beide Hybride.

**2. ml-kem-API weicht von der Erwartung ab.** Es gibt kein `KemCore` und kein
`EncodedSizeUser` in 0.3.4. Der Weg ist:
`DecapsulationKey::<MlKem768>::from(Seed)` → `dk.encapsulation_key()` →
`ek.encapsulate_deterministic(&B32)`. Für den 2400-Byte-DK braucht es
`ExpandedKeyEncoding::to_expanded_bytes()`; `to_bytes()` liefert nur den
64-Byte-Seed. Für den Import: `DecapsulationKey::from_expanded_bytes`.

**3. `ml-kem` mit Feature `alloc`.** Ohne `alloc` baut die Crate nicht. Das
betrifft nur den Hybrid-B-Pfad; der Basis-Crate bleibt unverändert.

**4. Teststruktur.** Statt 15 Tests zweimal zu schreiben, gibt es ein Makro
`hybrid_tests!`, das dieselben Prüfungen für beide Algorithmen erzeugt, plus drei
algorithmusübergreifende Tests (`hyb04`, `hyb05`, `hyb13_ohne_feature`). Dadurch
sind es 15 Tests bei Feature A, 16 bei Feature B und 29 bei beiden — die
Prüflogik ist identisch, nur die Zahl der Instanzen unterscheidet sich.

**5. RFC-Vektoren wörtlich.** Die X25519-Vektoren in `hyb05` sind aus
`https://www.rfc-editor.org/rfc/rfc7748.txt` kopiert (Abschnitt 5.2 und 6.1), nicht
aus dem Gedächtnis.

## Nicht geprüft

- **Kein Timing- oder Valgrind-Audit der Hybride.** `tests/ct_valgrind.rs` ist
  unverändert und deckt sie nicht ab. Die Constant-Time-Aussage gilt nur so weit,
  wie sie in `x25519-dalek` und `ml-kem` gilt; für den eigenen Kombinierer ist sie
  nicht belegt.
- **Kein unabhängiger ML-KEM-768-KAT.** `pip install kyber-py` wurde nicht
  versucht; `hyb15` prüft nur Größen gegen die Crate und die Rundreise innerhalb
  derselben Implementierung. Ein Fehler, den RustCrypto und kyber-py gemeinsam
  hätten, wäre nicht gefunden worden.
- **Kein `cargo clippy`.** Nicht installiert.
- **Kein Benchmark.** Es wurde keine Performance gemessen.
- **Kein Fuzzing der Hybride.** `fuzz/` ist unverändert.

## Offene Punkte

- `cargo clippy` sollte in der CI laufen; lokal fehlt es.
- Der Kombinierer ist nicht konstantzeitig geprüft.
- `x25519-dalek` 3.0.0 wäre langfristig die aktuellere Wahl; die Migration ist
  nicht untersucht.

## Abnahmekriterien

- [x] Basis-Tests unverändert grün (87), Debug und Release
- [x] Alle neuen Tests grün, beide Features, Debug und Release
- [x] Mutationsprobe 5 von 5 erkannt
- [x] `cargo build --no-default-features` sauber
- [x] Kein `unsafe`, kein neuer `unwrap` auf Netzdaten
- [x] Keine selbstgeschriebene Kurven-/ML-KEM-Arithmetik
- [x] README, HARNESSES.md, `docs/hybrid.md` aktualisiert, ohne
      „quantensicher“-Behauptung
- [x] Branch geliefert, `main` unberührt
- [x] Dieser Bericht
