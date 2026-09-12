---
last_reviewed: 2026-09-12
reviewed_by: CSTRSK
next_due_days: 180
---

# Crypto review log

Each entry records that the sources below were **read** at that date. This
file is checked by `.github/workflows/crypto-watch.yml`; the workflow fails
once `last_reviewed` is older than `next_due_days`.

The check cannot tell whether a new result matters. It can only tell that
nobody has looked — which is the failure mode that actually happens.

## What to look at

- [ ] **NIST PQC** — status of FIPS 203 (ML-KEM), 204 (ML-DSA), 205 (SLH-DSA);
      any announced successor or deprecation
- [ ] **CFRG** — `draft-irtf-cfrg-hybrid-kems` progress, and any change to the
      `LabeledHKDF` combiner this crate's hybrid would follow
- [ ] **BSI TR-02102-1** — current edition and its migration deadlines
- [ ] **Ring-LWE cryptanalysis** — new papers on `n=512`, `q=12289`, `η=8`;
      search ePrint for "Ring-LWE" + the parameter values
- [ ] **Fujisaki–Okamoto** — anything affecting the transform as implemented
      (`src/kem.rs`: re-encryption + implicit rejection)
- [ ] **Side channels** — published practical attacks on the deployment target
      (x86-64, AMD EPYC, no vetted constant-time assembler)

## Log

### 2026-09-12

Initial entry. Sources read:

- NIST PQC: FIPS 203/204/205 finalised; ML-KEM and ML-DSA are the standardised
  primitives. No successor announced.
- CFRG: `draft-irtf-cfrg-hybrid-kems` exists and defines the `LabeledHKDF`
  combiner used in the hybrid design notes (KitchenSink / QSF constructions).
  Not yet an RFC — the combiner should not be implemented against it yet for
  production, only noted.
- BSI TR-02102-1: hybrid requirement (classical + PQ) remains the guidance;
  no change that affects this crate.
- Ring-LWE at `n=512, q=12289, η=8`: no new result found that reduces the
  estimate below the published NewHope-512 margin.
- FO transform: nothing new affecting the implemented shape.
- Side channels: no new practical attack specific to this construction;
  the general caution (Python/NumPy cannot be constant time; Rust core is
  disciplined but not formally verified) remains.

**Conclusion:** no action required. The crate stays on `n=512`; `n=1024`
stays reserved and unoffered until it has been cross-validated.
