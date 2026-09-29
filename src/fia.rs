//! Testinstrument für Fault-Injection (nur mit Feature `fia-hooks`).
//!
//! Das Modell: ein einzelner transienter Fehler mitten in der Entkapselung.
//! Die Störung wird nicht über die Eingaben erzeugt (das wäre nur ein
//! manipulierter Chiffretext), sondern **im Zwischenvektor** der Rechnung —
//! also dort, wo eine Laser- oder Spannungsattacke tatsächlich ansetzt.
//!
//! Dieses Modul ist im Normalbau **nicht enthalten** (`#[cfg(feature = ...)]`
//! in `lib.rs` und an der Aufrufstelle in `kem.rs`), damit der ausgelieferte
//! Krypto-Pfad unverändert bleibt. Es ist ausdrücklich kein Produktivcode.
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::ntt::Poly;

static AKTIV: AtomicBool = AtomicBool::new(false);
static INDEX: AtomicUsize = AtomicUsize::new(0);
static BIT: AtomicUsize = AtomicUsize::new(0);

/// Scharf schalten: genau ein Bit an genau einer Stelle des Zwischenvektors.
pub fn scharf(index: usize, bit: usize) {
    INDEX.store(index, Ordering::SeqCst);
    BIT.store(bit, Ordering::SeqCst);
    AKTIV.store(true, Ordering::SeqCst);
}

/// Ausschalten (nach jedem Versuch aufrufen, sonst bleibt die Störung aktiv).
pub fn aus() {
    AKTIV.store(false, Ordering::SeqCst);
}

pub fn ist_scharf() -> bool {
    AKTIV.load(Ordering::SeqCst)
}

/// Kippt ein Bit im Zwischenvektor `w = v - u·s`.
pub(crate) fn anwenden<const N: usize>(poly: &mut Poly<N>) {
    if !ist_scharf() {
        return;
    }
    let i = INDEX.load(Ordering::SeqCst);
    let b = BIT.load(Ordering::SeqCst) & 15;
    if i < N {
        let neu = poly.coeffs[i].roh() ^ (1u16 << b);
        poly.coeffs[i].setze_roh(neu);
    }
}
