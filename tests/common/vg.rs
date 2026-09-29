//! Valgrind-Client-Requests ohne C-Abhängigkeit (Memcheck-API).
//!
//! Die Nummern stammen aus `/usr/include/valgrind/memcheck.h`:
//! `VG_USERREQ_TOOL_BASE('M','C')` = ('M' << 24) | ('C' << 16) = 0x4D430000,
//! danach in der Reihenfolge des Enums NOACCESS, UNDEFINED, DEFINED.
//! `RUNNING_ON_VALGRIND` (0x1001) und `COUNT_ERRORS` (0x1201) stehen in
//! `valgrind.h`.
#![allow(dead_code)]

pub const RUNNING_ON_VALGRIND: usize = 0x1001;
pub const COUNT_ERRORS: usize = 0x1201;
pub const MAKE_MEM_NOACCESS: usize = 0x4D43_0000;
pub const MAKE_MEM_UNDEFINED: usize = 0x4D43_0001;
pub const MAKE_MEM_DEFINED: usize = 0x4D43_0002;

/// Die magische Instruktionsfolge, an der Valgrind Client-Requests erkennt
/// (`__SPECIAL_INSTRUCTION_PREAMBLE` aus valgrind.h: viermal `rolq` auf rdi
/// und `xchgq %rbx,%rbx`).
///
/// `args[0]` ist die Anfragenummer, `args[1..]` bis zu fünf Argumente; der
/// Zeiger auf das Feld geht in `rax`, der Standardrückgabewert in `rdx`.
///
/// LLVM erlaubt `rbx` nicht als Asm-Operand ("used internally by LLVM"),
/// deshalb wird es hier ausdrücklich gesichert und wiederhergestellt — der
/// erzeugte Code ist damit korrekt, ohne rbx als Clobber zu deklarieren.
/// Die Reihenfolge der fünf Instruktionen bleibt unverändert, damit Valgrind
/// die Sequenz erkennt.
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
#[inline(always)]
fn request(default: usize, args: &[usize; 6]) -> usize {
    let mut result: usize = default;
    unsafe {
        core::arch::asm!(
            "push rbx",
            "rol rdi, 3",
            "rol rdi, 13",
            "rol rdi, 61",
            "rol rdi, 51",
            "xchg rbx, rbx",
            "pop rbx",
            inout("rax") args.as_ptr() as usize => _,
            inout("rdx") result,
            out("rdi") _,
            options(preserves_flags)
        );
    }
    result
}

#[cfg(not(all(target_arch = "x86_64", target_pointer_width = "64")))]
#[inline(always)]
fn request(default: usize, _args: &[usize; 6]) -> usize {
    default
}

/// Wahr, wenn der Prozess unter Valgrind läuft (sonst 0 = Standardwert).
pub fn running_on_valgrind() -> bool {
    request(0, &[RUNNING_ON_VALGRIND, 0, 0, 0, 0, 0]) != 0
}

/// Anzahl der bisher gemeldeten Fehler (nur unter Valgrind sinnvoll).
pub fn count_errors() -> usize {
    request(0, &[COUNT_ERRORS, 0, 0, 0, 0, 0])
}

fn annotate(req: usize, ptr: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    request(0, &[req, ptr as usize, len, 0, 0, 0]);
}

/// Markiert Speicher als "unbekannt" — die ct-grind-Technik: ab hier meldet
/// Valgrind jeden Sprung oder Speicherzugriff, der davon abhängt.
pub fn make_mem_undefined<T>(slice: &mut [T]) {
    annotate(MAKE_MEM_UNDEFINED, slice.as_ptr() as *const u8, core::mem::size_of_val(slice));
}

/// Markiert Speicher wieder als bekannt (vor Ausgaben oder Vergleichen).
pub fn make_mem_defined<T>(slice: &mut [T]) {
    annotate(MAKE_MEM_DEFINED, slice.as_ptr() as *const u8, core::mem::size_of_val(slice));
}

/// Markiert Speicher als nicht adressierbar.
pub fn make_mem_noaccess<T>(slice: &mut [T]) {
    annotate(MAKE_MEM_NOACCESS, slice.as_ptr() as *const u8, core::mem::size_of_val(slice));
}

/// Ein kleiner, deterministischer Zufallsstrom (xorshift64*), damit die
/// Harnesses reproduzierbar sind.
pub struct Rng(pub u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            let n = chunk.len();
            chunk.copy_from_slice(&v[..n]);
        }
    }

    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % (n as u64)) as usize
    }
}
