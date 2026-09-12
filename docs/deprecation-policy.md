# Deprecation policy

What happens when a parameter set or an algorithm in this crate is no longer
considered safe — and, more importantly, what **cannot** happen, so nobody
plans around a capability that does not exist.

This document is about reaction time, not about the current security level.

---

## 1. What can trigger a deprecation

| Trigger | Source | Typical notice |
|---------|--------|----------------|
| A new attack reduces the security estimate of the Ring-LWE regime (n=512, q=12289, η=8) | Cryptanalysis literature, NIST/CFRG discussion | years, but can be abrupt |
| A flaw is found in the Fujisaki–Okamoto transform or its implementation | Cryptanalysis | rare, but immediate |
| A standardised scheme is deprecated in favour of a successor | NIST PQC process, BSI TR-02102 | years, announced |
| A side-channel break becomes practical on the deployment target | Measurement, not literature | immediate |
| A peer/partner mandates a different primitive | Procurement | contractual |

The last two are the ones that actually force action quickly, and neither is
about the mathematics.

## 2. The hard truth: a KEM cannot be upgraded in place

**Ciphertexts already in the wild cannot be "migrated".** The shared secret
was derived when the ciphertext was produced. Re-running `decaps` with fixed
code changes nothing — the bytes and the secret are what they are.

Concretely, given a deployed system:

| Object | Can it be re-derived under a new algorithm? |
|--------|---------------------------------------------|
| Shared secret already used for a session | **No.** The session is over; if the traffic was recorded and the old KEM breaks, that traffic is exposed. |
| Stored ciphertext + secret key | Ciphertext: no. But the *payload* can be re-encrypted — see §3. |
| Long-term key pair | Yes, replaced by a new one. Nothing depends on the old bytes. |
| Data encrypted under a key derived from the old shared secret | Yes, by decrypting and re-encrypting — requires the plaintext to be available. |

**Consequence for planning:** anything that must survive a deprecation has to
be re-encrypted *before* the old scheme becomes practically breakable, while
the plaintext (or the derived key) is still available. There is no shortcut,
and no library can provide one.

## 3. What this crate's structure makes cheap

The agility work is exactly about not letting this become an emergency.

### The version byte identifies old data

Every stored object carries `[alg_id][len][body]` (`src/version.rs`). That
means an auditor, a migration script or a future version of this crate can
answer "which algorithm produced this?" from the bytes alone, without a side
table that can drift out of sync.

Reserved identifiers (`ReKem1024`, `MlKem768`, …) already exist, so a newer
writer's data is recognised — and reported as *"known but not enabled in this
build"* rather than as corruption. That distinction is what makes a staged
rollout possible.

### The registry allows both algorithms to run at once

`api::Registry` maps identifiers to implementations. During a transition you
register the old and the new side by side and route by the identifier read
from the stored object. No call site changes — that is the whole point of
`api::Kem` being object-safe.

### The parameter set is one value

`params::ACTIVE` is the single place `n`, `q` and `η` are chosen. A second
set (`params::LEVEL5_1024`) is already declared with its sizes, so the
mechanical work of a parameter change is confined to the arithmetic that
genuinely depends on `n` — not to hunting constants across four modules.

## 4. The migration procedure

If a parameter set is declared unsafe, the order is:

1. **Stop producing.** Flip `params::ACTIVE` to the successor and register
   both sets in the `Registry`. New keys, new ciphertexts.
2. **Re-encrypt at rest, oldest first.** Walk stored data, use the version
   byte to select the old implementation, decrypt, re-encrypt under the new
   one, and rewrite the envelope. This is a data migration, and its cost is
   proportional to the data volume — not to the code.
3. **Keep decapsulation for the old set** until the last object that needs it
   has been re-encrypted. Decapsulation is the only capability that must
   outlive production.
4. **Retire.** Remove the old implementation. The identifier stays in the
   registry permanently (never renumber), so old data is still recognised and
   rejected with a clear message instead of silently mis-parsed.

### Hybridisation is the pressure valve

If RE-KEM is used in the hybrid construction (`LabeledHKDF(pq_ss ‖ trad_ss ‖
…)`), the security holds as long as **one** component holds. A weakening of
the Ring-LWE side therefore does *not* force an immediate migration — the
transition can be planned instead of rushed. This is the main practical
argument for hybrid deployment beyond migration economics.

## 5. What this crate does not claim

- **No formal verification.** The constant-time property is argued from the
  absence of secret-dependent branches and measured with a dudect-style test.
  That is evidence, not proof.
- **No warranty for the parameter set.** `n=512, q=12289, η=8` follows a
  published regime; the crate does not re-derive its security estimates.
- **The reserved `n=1024` set is not offered.** Its sizes are known, its
  arithmetic is untested against an independent implementation, and
  `Algorithm::ReKem1024::is_offered()` returns `false` accordingly. Offering
  an unvalidated parameter set would be worse than offering none.

## 6. Observation duty

Nothing in this repository watches the literature automatically. The
following are read at release time and are listed in the README so they are
not forgotten:

- NIST PQC announcements and the status of FIPS 203/204/205
- CFRG drafts: `draft-irtf-cfrg-hybrid-kems` and any successor
- BSI TR-02102-1 (annual), especially the migration deadlines
- The ePrint/cryptanalysis record for Ring-LWE at `n=512` with `η=8`

A scheduled check is provided as a GitHub Actions workflow
(`.github/workflows/crypto-watch.yml`) that fails when none of these sources
has been reviewed within the configured window. It is a reminder, not a
scanner — it cannot tell whether a new paper matters, only that nobody has
looked.
