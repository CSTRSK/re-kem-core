//! Known-Answer-Tests gegen die Python-Referenz (`rekem.py`).
//!
//! Die Vektordateien im Repo stammen von der **Python-Seite**
//! (`tools/cross_kem_python.py`), nicht aus diesem Crate:
//!
//! | Datei          | Parametersatz | Runden | Quelle                          |
//! |----------------|---------------|--------|---------------------------------|
//! | `py.json`      | n = 512       | 10 000 | Python-Referenz                 |
//! | `py-1024.json` | n = 1024      |  1 000 | Python-Referenz                 |
//! | `vectors.json` | Körper mod q  | ~ 20 k | add/sub/mul, hier mathematisch geprüft |
//!
//! Jede Runde leitet ihre Seeds als `sha256("re-kem-cross-<i>-<label>")` ab,
//! führt keygen/encaps deterministisch aus und vergleicht SHA-256(pk),
//! SHA-256(ct) und das Shared Secret mit der Datei. Damit sind auch **sehr
//! seltene** Abweichungen (z. B. ein Randfall der Rejection-Sampling-Grenze,
//! die nur bei etwa einem von 65 536 Wörtern auftritt) abgedeckt, die
//! Stichproben-Tests nicht sehen.
//!
//! Umfang:
//!   Release-Profil: alle Runden.   Debug-Profil: 200 bzw. 50 Runden.
//!   Überschreiben: `KAT_RUNDEN=<zahl>` oder `KAT_RUNDEN=alle`.
//!
//! Neu erzeugen (nur bei bewusster Änderung des Wire-Formats!):
//!   PYTHONPATH=<pfad-zu-RE-KEM> python3 tools/cross_kem_python.py 10000 512  > py.json
//!   PYTHONPATH=<pfad-zu-RE-KEM> python3 tools/cross_kem_python.py  1000 1024 > py-1024.json

use re_kem_core::{FieldElement, KemGeneric, ReKem, ReKem1024, Q};
use sha2::{Digest, Sha256};

// ───────────────────────────── Hilfsfunktionen ─────────────────────────────

fn lies(datei: &str) -> String {
    let pfad = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), datei);
    std::fs::read_to_string(&pfad).unwrap_or_else(|e| panic!("{pfad} nicht lesbar: {e}"))
}

/// Alle String-Werte zu `"<schluessel>"` in Dateireihenfolge.
/// (Bewusst ohne JSON-Abhängigkeit: das Format ist flach und regelmäßig.)
fn text_werte(json: &str, schluessel: &str) -> Vec<String> {
    let muster = format!("\"{schluessel}\"");
    let mut out = Vec::new();
    let mut rest = json;
    while let Some(p) = rest.find(&muster) {
        rest = &rest[p + muster.len()..];
        let doppelpunkt = rest.find(':').expect("':' fehlt");
        rest = &rest[doppelpunkt + 1..];
        let von = rest.find('"').expect("Wert fehlt") + 1;
        let bis = von + rest[von..].find('"').expect("Wert unterminiert");
        out.push(rest[von..bis].to_string());
        rest = &rest[bis + 1..];
    }
    out
}

/// Alle Ganzzahl-Werte zu `"<schluessel>"` in Dateireihenfolge.
fn zahl_werte(json: &str, schluessel: &str) -> Vec<u64> {
    let muster = format!("\"{schluessel}\"");
    let mut out = Vec::new();
    let mut rest = json;
    while let Some(p) = rest.find(&muster) {
        rest = &rest[p + muster.len()..];
        let doppelpunkt = rest.find(':').expect("':' fehlt");
        rest = rest[doppelpunkt + 1..].trim_start();
        let ende = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        out.push(rest[..ende].parse().expect("keine Zahl"));
        rest = &rest[ende..];
    }
    out
}

fn seed(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

fn hex(daten: &[u8]) -> String {
    daten.iter().map(|b| format!("{b:02x}")).collect()
}

fn runden(vorhanden: usize, release: usize, debug: usize) -> usize {
    let wunsch = match std::env::var("KAT_RUNDEN").ok().as_deref() {
        Some("alle") => vorhanden,
        Some(z) => z.parse().expect("KAT_RUNDEN: Zahl oder 'alle'"),
        None if cfg!(debug_assertions) => debug,
        None => release,
    };
    wunsch.min(vorhanden)
}

// ───────────────────────────── KEM-Vektoren ───────────────────────────────

fn pruefe_kem<const N: usize, const PK: usize, const SK: usize, const CT: usize>(
    kem: &KemGeneric<N, PK, SK, CT>,
    datei: &str,
    erwartet_gesamt: usize,
    release: usize,
    debug: usize,
) {
    let json = lies(datei);
    let idx = zahl_werte(&json, "i");
    let pk_sha = text_werte(&json, "pk_sha");
    let ct_sha = text_werte(&json, "ct_sha");
    let ss = text_werte(&json, "ss");

    // Eine leere oder abgeschnittene Datei darf den Test nicht still bestehen lassen.
    assert_eq!(idx.len(), erwartet_gesamt, "{datei}: Rundenzahl");
    assert_eq!(pk_sha.len(), erwartet_gesamt, "{datei}: pk_sha-Zahl");
    assert_eq!(ct_sha.len(), erwartet_gesamt, "{datei}: ct_sha-Zahl");
    assert_eq!(ss.len(), erwartet_gesamt, "{datei}: ss-Zahl");
    assert!(
        idx.iter().enumerate().all(|(k, &i)| i == k as u64),
        "{datei}: Indizes nicht lückenlos 0..n"
    );

    let n_runden = runden(erwartet_gesamt, release, debug);
    for i in 0..n_runden {
        let seed_a = seed(&format!("re-kem-cross-{i}-seedA"));
        let noise = seed(&format!("re-kem-cross-{i}-noise"));
        let z = seed(&format!("re-kem-cross-{i}-z"));
        let m = seed(&format!("re-kem-cross-{i}-msg"));

        let (pk, sk) = kem.keygen_derand(&seed_a, &noise, &z);
        let (ct, secret) = kem.encaps_derand(&pk, &m);

        assert_eq!(hex(&Sha256::digest(&pk[..])), pk_sha[i], "{datei} n={N} Runde {i}: pk");
        assert_eq!(hex(&Sha256::digest(&ct[..])), ct_sha[i], "{datei} n={N} Runde {i}: ct");
        assert_eq!(hex(&secret), ss[i], "{datei} n={N} Runde {i}: Shared Secret");
        assert_eq!(kem.decaps(&sk, &ct), secret, "{datei} n={N} Runde {i}: decaps");
    }
}

#[test]
fn kat01_n512_gegen_python_referenz() {
    pruefe_kem(&ReKem::new(), "py.json", 10_000, 10_000, 200);
}

#[test]
fn kat02_n1024_gegen_python_referenz() {
    pruefe_kem(&ReKem1024::new(), "py-1024.json", 1_000, 1_000, 50);
}

#[test]
fn kat03_die_beiden_parametersaetze_liefern_verschiedene_vektoren() {
    // Schutz davor, dass jemand versehentlich dieselbe Datei für beide Sätze ablegt:
    // gleiche Seed-Labels, aber andere Ringe => andere Hashes.
    let a = text_werte(&lies("py.json"), "pk_sha");
    let b = text_werte(&lies("py-1024.json"), "pk_sha");
    assert_ne!(a[0], b[0]);
    assert_ne!(a[1], b[1]);
}

#[test]
fn kat04_vektoren_sind_paarweise_verschieden() {
    // Doppelte Hashes würden auf eine defekte Seed-Ableitung deuten.
    for datei in ["py.json", "py-1024.json"] {
        let mut pks = text_werte(&lies(datei), "pk_sha");
        let mut sss = text_werte(&lies(datei), "ss");
        let (np, ns) = (pks.len(), sss.len());
        pks.sort();
        pks.dedup();
        sss.sort();
        sss.dedup();
        assert_eq!(pks.len(), np, "{datei}: doppelte pk_sha");
        assert_eq!(sss.len(), ns, "{datei}: doppelte ss");
    }
}

// ───────────────────────────── Körper-Vektoren ────────────────────────────

#[test]
fn kat05_koerpervektoren_add_sub_mul() {
    let json = lies("vectors.json");
    assert_eq!(zahl_werte(&json, "q"), vec![Q as u64], "Modul q der Datei");
    assert_eq!(zahl_werte(&json, "modulus_q"), vec![Q as u64]);

    let a = zahl_werte(&json, "a");
    let b = zahl_werte(&json, "b");
    let add = zahl_werte(&json, "add");
    let sub = zahl_werte(&json, "sub");
    let mul = zahl_werte(&json, "mul");
    let n = a.len();
    assert!(n >= 1000, "zu wenige Vektoren: {n}");
    assert!(b.len() == n && add.len() == n && sub.len() == n && mul.len() == n);

    let q = Q as u64;
    for k in 0..n {
        let (x, y) = (a[k], b[k]);
        assert!(x < q && y < q, "Vektor {k}: Operand außerhalb [0, q)");

        // 1. Die Datei selbst muss mathematisch stimmen (schützt vor defekter Datei) …
        assert_eq!(add[k], (x + y) % q, "Datei Vektor {k}: add");
        assert_eq!(sub[k], (x + q - y) % q, "Datei Vektor {k}: sub");
        assert_eq!(mul[k], (x * y) % q, "Datei Vektor {k}: mul");

        // 2. … und die Implementierung muss sie reproduzieren.
        let (fx, fy) = (FieldElement::from_plain(x as u16), FieldElement::from_plain(y as u16));
        assert_eq!(fx.add(fy).to_plain() as u64, add[k], "Vektor {k}: add");
        assert_eq!(fx.sub(fy).to_plain() as u64, sub[k], "Vektor {k}: sub");
        assert_eq!(fx.mul(fy).to_plain() as u64, mul[k], "Vektor {k}: mul");
    }
}
