# Hybride KEMs (experimentell)

Zwei Hybride aus je einem PQ-KEM und X25519. **Nicht standardisiert, nicht
X-Wing-kompatibel, kein externes Audit.** Der Quantenschutz hängt allein am
PQ-Teil; X25519 liefert nur klassische Absicherung zusätzlich.

## Warum überhaupt hybrid

Ein PQ-KEM ist neu. Ein Fehler in der algebraischen Struktur wäre für einen
Angreifer mit Quantenrechner verwertbar, ohne dass klassische Prüfungen ihn
zeigen. X25519 ist seit zwei Jahrzehnten analysiert. Kombiniert man beide, muss
ein Angreifer **beide** brechen — solange der Kombinierer nichts von einem der
beiden Teile preisgibt.

## Algorithmus A: `HybridReKem512X25519` (ID `0x81`)

| Objekt | Aufbau | Länge |
|---|---|---|
| Öffentlicher Schlüssel | `rekem_pk (1056) ‖ x25519_pk (32)` | 1088 |
| Geheimer Schlüssel | `rekem_sk (2144) ‖ x25519_sk (32) ‖ x25519_pk (32)` | 2208 |
| Chiffretext | `rekem_ct (2048) ‖ x25519_eph_pk (32)` | 2080 |
| Shared Secret | — | 32 |

PQ-Teil: das bestehende `ReKem` (n = 512, q = 12289, η = 8).

## Algorithmus B: `HybridMlKem768X25519` (ID `0x90`)

| Objekt | Aufbau | Länge |
|---|---|---|
| Öffentlicher Schlüssel | `mlkem768_ek (1184) ‖ x25519_pk (32)` | 1216 |
| Geheimer Schlüssel | `mlkem768_dk (2400) ‖ x25519_sk (32) ‖ x25519_pk (32)` | 2464 |
| Chiffretext | `mlkem768_ct (1088) ‖ x25519_eph_pk (32)` | 1120 |
| Shared Secret | — | 32 |

PQ-Teil: ML-KEM-768 nach FIPS 203, aus der RustCrypto-Crate `ml-kem`. Die
Größen 1184 / 2400 / 1088 sind im Test `hyb15` gegen das Crate geprüft, nicht
aus dem Gedächtnis übernommen.

## Ablauf

**keygen**
1. `(pq_pk, pq_sk)` vom PQ-Verfahren.
2. `x_sk` = 32 Zufallsbyte, `x_pk = X25519(x_sk, Basispunkt)`.
3. `x_pk` wird **zusätzlich** im sk abgelegt, damit `decaps` den Kombinierer mit
   demselben Empfänger-Schlüssel binden kann wie `encaps`.

**encaps(pk)**
1. pk zerlegen, Länge exakt prüfen.
2. `(pq_ct, pq_ss) = PQ.encaps(pq_pk)`.
3. `e` = 32 Zufallsbyte, `x_ct = X25519(e, Basispunkt)`, `x_ss = X25519(e, x_pk)`.
4. Ist `x_ss` komplett Null (Punkt kleiner Ordnung): `KemError::InvalidPublicKey`.
5. `ct = pq_ct ‖ x_ct`, `ss = Kombinierer(...)`.

**decaps(sk, ct)**
1. sk und ct zerlegen, Längen prüfen.
2. `pq_ss = PQ.decaps(pq_sk, pq_ct)` — die implizite Ablehnung des PQ-Teils
   bleibt erhalten.
3. `x_ss = X25519(x_sk, x_ct)`.
4. Bei Null-`x_ss` **nicht** abbrechen: mit dem Nullwert weiterrechnen. Ein
   Abbruch wäre ein Orakel; so ist das Ergebnis deterministisch und für einen
   Angreifer unbrauchbar.
5. `ss = Kombinierer(...)`.

## Der Kombinierer

```
ss = SHA3-256(
        "re-kem-core/hybrid/v1"      // 21 Byte ASCII, ohne Nullbyte
     ‖  algorithm_id                 // 1 Byte: 0x81 oder 0x90
     ‖  pq_ss                        // 32 Byte
     ‖  x_ss                         // 32 Byte
     ‖  pq_ct                        // 2048 bzw. 1088 Byte
     ‖  x_ct                         // 32 Byte
     ‖  x_pk                         // 32 Byte (Empfänger-pk)
   )
```

Reihenfolge und Längen sind verbindlich. Die Vektoren in
`tests/hybrid_kombinierer.json` entstehen aus `tools/hybrid_referenz.py`, das
denselben Ausdruck in reinem Python mit `hashlib.sha3_256` nachrechnet.

### Warum genau diese Bindung

**Beide Shared Secrets** — sonst wäre der Hybrid nur so stark wie der stärkere
Teil, und ein Angreifer könnte den schwächeren ignorieren.

**Algorithmus-ID** — verhindert, dass ein Secret zwischen A und B verschoben
wird. Ohne die ID hätte ein hybrides Secret in beiden Kontexten denselben Wert,
und ein Downgrade-Angriff wäre denkbar.

**Beide Chiffretexte** — schützt vor Mix-and-Match. Ohne die Bindung an `pq_ct`
und `x_ct` könnte ein Angreifer `pq_ct` aus Sitzung 1 mit `x_ct` aus Sitzung 2
kombinieren; der Test `hyb08` prüft genau diesen Fall.

**Empfänger-Schlüssel `x_pk`** — bindet das Secret an den vorgesehenen
Empfänger. Ohne diese Bindung wäre ein Secret gültig, das gegen einen anderen
öffentlichen Schlüssel erzeugt wurde. Test `hyb09`.

Die Struktur ist bewusst **nicht** X-Wing. X-Wing verwendet SHA3-256 über
`ss_M ‖ ss_X ‖ ct_X ‖ pk_X` mit einem festen Präfix und ohne PQ-Chiffretext.
Wer Kompatibilität braucht, muss X-Wing implementieren, nicht dieses Format.

## Feature-Flags

```toml
hybrid-rekem-x25519 = ["dep:x25519-dalek"]
hybrid-mlkem-x25519 = ["dep:x25519-dalek", "dep:ml-kem"]
```

Beide sind standardmäßig **aus**. Ohne Feature bleibt der Basis-Crate
unverändert und `no_std`-fähig.

## Grenzen

- **Kein Timing-Audit.** `tests/ct_valgrind.rs` deckt die Hybride nicht ab. Die
  Constant-Time-Aussage gilt nur so weit, wie sie in `x25519-dalek` und
  `ml-kem` gilt — für den eigenen Kombinierer ist sie nicht belegt.
- **Kein unabhängiger ML-KEM-KAT.** Für ML-KEM-768 gibt es keinen gegen eine
  zweite Implementierung geprüften Vektor; `hyb15` prüft nur Größen und die
  Rundreise innerhalb derselben Crate.
- **Kein externes Audit.** Diese Hybride sind Experimentiercode.
