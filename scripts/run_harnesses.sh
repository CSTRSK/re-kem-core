#!/usr/bin/env bash
# CI-Einstieg für die vier Härtungs-Harnesses des Crates.
#
#   Exitcode 0  = alles grün
#   Exitcode >0 = Befund (Leck, Absturz, Abweichung)
#
# Umgebungsvariablen:
#   FUZZ_SEKUNDEN  Budget für das Differential-Fuzzing (Standard 60)
#   OHNE_VALGRIND  =1 überspringt die beiden Valgrind-Schritte
set -uo pipefail

HIER="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HIER"
FUZZ_SEKUNDEN="${FUZZ_SEKUNDEN:-60}"
OHNE_VALGRIND="${OHNE_VALGRIND:-0}"
FEHLER=0

kopf() { printf '\n────────────────────────────────────────────────────────\n%s\n────────────────────────────────────────────────────────\n' "$1"; }
ok()   { printf '  OK    %s\n' "$1"; }
fehler_melden() { printf '  FEHLER %s\n' "$1"; FEHLER=1; }

# Pfad des Testbinärs über cargo ermitteln (nicht raten).
test_binary() {
    local name="$1"; shift
    cargo test --release "$@" --test "$name" --no-run --message-format=json 2>/dev/null \
        | python3 -c '
import json, sys
pfad = ""
for zeile in sys.stdin:
    try:
        d = json.loads(zeile)
    except Exception:
        continue
    if d.get("reason") == "compiler-artifact" and d.get("executable"):
        if d.get("target", {}).get("name") == sys.argv[1] and "test" in d.get("target", {}).get("kind", []):
            pfad = d["executable"]
print(pfad)
' "$name"
}

kopf "Bau (Release, mit und ohne Feature fia-hooks)"
if cargo build --release --tests >/dev/null 2>&1 && \
   cargo build --release --tests --features fia-hooks >/dev/null 2>&1; then
    ok "beide Profile bauen"
else
    fehler_melden "Bau fehlgeschlagen"; exit 2
fi

kopf "0) Ungeprüfte Bytes auf dem Draht — Debug-Build (Panikfreiheit)"
if cargo test --test decode_untrusted 2>&1 | tail -3; then
    ok "decode_untrusted (Debug: debug_assertions aktiv)"
else
    fehler_melden "decode_untrusted (Debug)"
fi

kopf "3) IND-CCA2 und Implicit Rejection"
if cargo test --release --test ind_cca2 2>&1 | tail -3; then ok "ind_cca2"; else fehler_melden "ind_cca2"; fi

kopf "4) Fault-Injection, äußere Störungen (sk / ct)"
if cargo test --release --test fia -- --nocapture 2>&1 | tail -6; then ok "fia (ohne Feature)"; else fehler_melden "fia (ohne Feature)"; fi

kopf "4b) Fault-Injection, innere Störung im Zwischenvektor"
if cargo test --release --features fia-hooks --test fia -- --nocapture 2>&1 | tail -9; then
    ok "fia (mit fia-hooks)"; else fehler_melden "fia (mit fia-hooks)"; fi

if [ "$OHNE_VALGRIND" != "1" ]; then
    if ! command -v valgrind >/dev/null; then
        fehler_melden "valgrind fehlt (dnf install valgrind valgrind-devel)"
    else
        VG=(valgrind --tool=memcheck --error-exitcode=99 --leak-check=no --track-origins=yes)

        kopf "1) Positivkontrolle: erkennt der Audit überhaupt ein Leck?"
        KBIN="$(test_binary ct_control)"
        if [ -z "$KBIN" ]; then
            fehler_melden "Kontrollbinary nicht gefunden"
        else
            "${VG[@]}" "$KBIN" >/tmp/ct_kontrolle.log 2>&1
            if [ $? -eq 99 ]; then
                ok "Kontrolle gemeldet ($(grep -c 'uninitialised' /tmp/ct_kontrolle.log) Meldungen, Log /tmp/ct_kontrolle.log)"
            else
                fehler_melden "Kontrolle hat KEIN Leck gemeldet — der Audit misst nichts"
            fi
        fi

        kopf "1) Constant-Time-Audit der Bibliothek"
        VBIN="$(test_binary ct_valgrind)"
        if [ -z "$VBIN" ]; then
            fehler_melden "Auditbinary nicht gefunden"
        else
            "${VG[@]}" "$VBIN" --test-threads=1 --nocapture >/tmp/ct_audit.log 2>&1
            VG_EXIT=$?
            if ! grep -q "valgrind aktiv: true" /tmp/ct_audit.log; then
                # Ohne Valgrind sind die Client-Requests No-ops: ein "grüner" Lauf
                # ohne diese Zeile wäre wertlos.
                fehler_melden "Valgrind war nicht aktiv — Audit ungültig"
            elif [ "$VG_EXIT" -eq 0 ]; then
                ok "0 Fehler unter Valgrind"
            else
                fehler_melden "Valgrind meldet $(grep -o 'ERROR SUMMARY: [0-9]*' /tmp/ct_audit.log | tail -1) — Log /tmp/ct_audit.log"
            fi
        fi
    fi
fi

kopf "2) Differential-Fuzzing NTT gegen naive Faltung (${FUZZ_SEKUNDEN}s)"
if ! command -v cargo-fuzz >/dev/null; then
    fehler_melden "cargo-fuzz fehlt (cargo install cargo-fuzz)"
else
    if cargo +nightly fuzz run ntt_algebra -- -max_len=4096 -rss_limit_mb=900 \
            -max_total_time="$FUZZ_SEKUNDEN" >/tmp/fuzz_report.log 2>&1; then
        ok "$(grep -o 'Done [0-9]* runs' /tmp/fuzz_report.log | tail -1) ohne Abweichung"
    else
        if grep -q "failed to build fuzz script" /tmp/fuzz_report.log; then
            fehler_melden "Fuzzing-Target ließ sich nicht bauen (Log /tmp/fuzz_report.log)"
        elif grep -qE "deadly signal|SUMMARY: libFuzzer|assertion failed" /tmp/fuzz_report.log; then
            fehler_melden "Fuzzing hat einen Absturz gefunden (Artefakt unter fuzz/artifacts/)"
        else
            fehler_melden "Fuzzing abgebrochen (Log /tmp/fuzz_report.log)"
        fi
    fi
fi

kopf "Ergebnis"
if [ "$FEHLER" -eq 0 ]; then
    echo "  alle Harnesses grün"
else
    echo "  mindestens ein Befund — siehe oben"
fi
exit "$FEHLER"
