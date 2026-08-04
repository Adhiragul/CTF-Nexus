"""
Decompiled-code analysis + dynamic-analysis planning.

This is the answer to "I decompiled it in Ghidra, now what": paste the
pseudocode Ghidra (or radare2/Binary Ninja) produced and get it scanned for
the patterns that actually matter in a CTF - a strcmp/memcmp against a
literal (password/flag check), a dangerous function (classic overflow),
a symmetric encode/decode loop (XOR/rotate - the key is usually recoverable
statically), and any string literals that might themselves be encoded flag
data.

This deliberately does NOT try to be a real decompiler or execute anything -
it's a fast pattern pass over text you already produced with a real tool.
Actually running the target binary (dynamic analysis) is a different, riskier
problem - see generate_dynamic_plan() below, which only ever generates a
pwntools script template based on `checksec`-style protection flags; it
never executes the untrusted binary itself.
"""

from __future__ import annotations

import re
from typing import List, Optional

from ..base import AnalysisResult, Finding
from ...flag_formats import scan as scan_flags

DANGEROUS_FUNCS = {
    "gets": "Never bounds-checked - classic stack buffer overflow entry point. Look at the buffer it writes into and its declared size.",
    "strcpy": "No bounds checking - overflow if source can exceed destination size.",
    "strcat": "Same class as strcpy - check destination buffer size vs source length.",
    "sprintf": "No bounds checking on the output buffer - check for a format string vuln too if the format string itself is user-controlled.",
    "scanf": "%s with no width specifier overflows just like gets().",
    "system": "Command execution - if any part of the argument is user-controlled, this is a command injection / shell primitive.",
    "exec": "Process execution primitive - check what's controllable in the arguments.",
    "memcpy": "Bounds depend entirely on the length argument - check whether that length is user-controlled.",
    "alloca": "Stack allocation with a runtime size - if that size is user-controlled, can be used to smash the stack directly.",
}

COMPARISON_FUNCS = ["strcmp", "strncmp", "memcmp", "strcasecmp"]


def _extract_string_literals(code: str) -> List[str]:
    # naive but effective: C string literals, unescaping the common escapes
    raw = re.findall(r'"((?:[^"\\]|\\.)*)"', code)
    return [r.encode().decode("unicode_escape", errors="ignore") for r in raw]


def analyze_decompiled_code(code: str) -> AnalysisResult:
    findings: List[Finding] = []
    next_steps: List[str] = []

    # --- comparison-based checks: the classic "if (strcmp(input, X) == 0)" ---
    for func in COMPARISON_FUNCS:
        for m in re.finditer(rf"\b{func}\s*\(([^;]*?)\)", code):
            args = m.group(1)
            findings.append(Finding(
                label=f"comparison_check:{func}",
                summary=f"{func}({args.strip()[:120]})",
                confidence=0.75,
                detail={"line_context": code[max(0, m.start()-60):m.end()+20].strip()},
            ))
    if any(f.label.startswith("comparison_check") for f in findings):
        next_steps.append(
            "Comparison against a literal found - if this gates the 'win' path, either patch the "
            "conditional jump directly in the binary, or the literal itself may just be the flag/password."
        )

    # --- dangerous functions ---------------------------------------------------
    for func, note in DANGEROUS_FUNCS.items():
        pattern = rf"\b{func}\s*\("
        matches = list(re.finditer(pattern, code))
        if matches:
            findings.append(Finding(
                label=f"dangerous_func:{func}",
                summary=f"{func}() called {len(matches)}x - {note}",
                confidence=0.8,
            ))
    if any(f.label.startswith("dangerous_func:gets") or f.label.startswith("dangerous_func:scanf") for f in findings):
        next_steps.append("An unbounded input function was found - this is very likely a buffer-overflow / pwn challenge. Check checksec output for canary/NX/PIE before planning the exploit.")
    if any(f.label == "dangerous_func:system" for f in findings):
        next_steps.append("system() is called somewhere - check if any argument traces back to user input (command injection) or if there's a way to control PATH/argv[0] for a ret2libc-style system('/bin/sh') win.")

    # --- symmetric encode/decode loops (XOR, rotate) - key is often recoverable
    xor_loops = re.findall(r"\^=?\s*(0x[0-9a-fA-F]+|\d+)", code)
    if xor_loops:
        keys = sorted(set(xor_loops), key=xor_loops.index)
        findings.append(Finding(
            label="xor_operation",
            summary=f"XOR operation(s) found with constant operand(s): {keys[:10]}",
            confidence=0.6,
            detail={"keys_seen": keys[:10]},
        ))
        next_steps.append(f"XOR with a constant key was found ({keys[:5]}) - if this decodes a hardcoded byte array into the flag, you can likely compute the flag statically without running the binary at all.")

    rotate_ops = re.findall(r"(<<|>>)\s*\d+", code)
    if rotate_ops:
        findings.append(Finding(label="bit_rotate_shift", summary=f"{len(rotate_ops)} bit-shift/rotate operation(s) found - possible custom encoding routine.", confidence=0.4))

    # --- hardcoded byte arrays: possible encoded flag/key ------------------------
    byte_arrays = re.findall(r"(?:unsigned\s+char|uint8_t|BYTE)\s+\w+\s*\[\s*\d*\s*\]\s*=\s*\{([^}]+)\}", code)
    if byte_arrays:
        findings.append(Finding(
            label="hardcoded_byte_array",
            summary=f"{len(byte_arrays)} hardcoded byte array(s) found - likely an encoded flag, key, or lookup table.",
            confidence=0.65,
            data=byte_arrays[0][:500],
        ))
        next_steps.append("A hardcoded byte array was found - try XOR/rotate-decoding it with any key found nearby, or just paste the bytes into the Crypto tab's hex/XOR detector.")

    # --- string literals: flag-scan them directly, and note anything interesting -
    literals = _extract_string_literals(code)
    if literals:
        literal_text = "\n".join(literals)
        flags = scan_flags(literal_text)
        interesting = [s for s in literals if len(s) > 3][:30]
        findings.append(Finding(
            label="string_literals",
            summary=f"{len(literals)} string literal(s) extracted from the decompiled source",
            confidence=0.5,
            data="\n".join(interesting),
            flags_found=flags,
        ))
        if flags:
            next_steps.insert(0, f"Flag pattern found directly in a string literal: {flags}")

    # --- function-name heuristics (win(), backdoor(), check_flag(), etc.) ---------
    interesting_func_names = re.findall(r"\b(\w*(?:win|backdoor|secret|flag|debug|admin)\w*)\s*\(", code, re.IGNORECASE)
    interesting_func_names = sorted(set(n for n in interesting_func_names if n.lower() not in ("strcmp", "memcmp")))
    if interesting_func_names:
        findings.append(Finding(
            label="interesting_function_names",
            summary=f"Function name(s) worth investigating: {interesting_func_names}",
            confidence=0.7,
        ))
        next_steps.insert(0, f"Function(s) named {interesting_func_names} stand out - check if they're reachable from main() and whether there's an unintended path to call them (ret2win candidate).")

    if not findings:
        next_steps.append("No obvious patterns matched. This may be doing real cryptography (AES/RSA) rather than a simple obfuscation - check for library calls (OpenSSL, mbedtls symbol names) instead.")

    return AnalysisResult(
        plugin="reverse.decompiled_analyzer",
        category="reverse",
        findings=findings,
        tool_log=["static pattern analysis of pasted decompiled source - no execution"],
        next_steps=next_steps,
    )


# ---------------------------------------------------------------------------
# Dynamic-analysis planning
# ---------------------------------------------------------------------------
# Deliberately does NOT execute the uploaded binary - CTF binaries are
# untrusted-by-definition and auto-running them would be a real RCE risk in
# a shared/automated tool. Instead this generates the pwntools skeleton and
# gdb/pwndbg cheatsheet a human would write next, based on the protections
# already detected by reverse.analyzer.analyze_binary()'s checksec step.

def generate_dynamic_plan(checksec_output: Optional[str], binary_name: str = "./chall") -> AnalysisResult:
    findings: List[Finding] = []
    next_steps: List[str] = []

    canary = nx = pie = relro_full = False
    parsed = False

    # preferred path: checksec --format=json output, e.g.
    # { "/path": {"relro":"partial","canary":"no","nx":"yes","pie":"no",...} }
    if checksec_output:
        import json as _json
        try:
            data = _json.loads(checksec_output)
            entry = next(iter(data.values())) if isinstance(data, dict) else None
            if isinstance(entry, dict):
                canary = str(entry.get("canary", "")).lower() == "yes"
                nx = str(entry.get("nx", "")).lower() == "yes"
                pie = str(entry.get("pie", "")).lower() in ("yes", "pie")
                relro_full = str(entry.get("relro", "")).lower() == "full"
                parsed = True
        except (ValueError, StopIteration):
            pass

    # fallback: plain-text checksec output (older versions, or hand-pasted),
    # ANSI color codes stripped first since terminals often leave them in
    if not parsed and checksec_output:
        text = re.sub(r"\x1b\[[0-9;]*m", "", checksec_output).lower()
        canary = ("no canary" not in text) and ("canary found" in text)
        nx = ("nx enabled" in text) or ("nx" in text and "disabled" not in text and "no nx" not in text)
        pie = ("pie enabled" in text) and ("no pie" not in text)
        relro_full = "full relro" in text

    protections = {"canary": canary, "nx": nx, "pie": pie, "full_relro": relro_full}
    findings.append(Finding(label="protection_summary", summary=str(protections), confidence=0.7 if checksec_output else 0.2, detail=protections))

    lines = [
        "from pwn import *", "",
        f"elf = ELF('{binary_name}')",
        "context.binary = elf",
        "",
        "# io = process(elf.path)          # local",
        "# io = remote('HOST', PORT)       # remote, once you have the target",
        "io = gdb.debug(elf.path, gdbscript='''",
        "    break *main",
        "    continue",
        "''')  # comment this out once you're past initial exploration",
        "",
    ]

    if not canary:
        next_steps.append("No stack canary - direct return-address overwrite is on the table, no leak needed for that part.")
        lines.append("# no canary - straight buffer overflow to overwrite the saved return address")
    else:
        next_steps.append("Canary present - you need an info leak (format string, off-by-one read, etc.) before you can safely smash the stack, or find a path that doesn't go through the canary at all (e.g. overwriting a different variable).")
        lines.append("# canary present - need a leak before touching the return address")

    if not nx:
        next_steps.append("NX disabled - shellcode on the stack is viable, no ROP needed.")
        lines.append("payload = b'A' * OFFSET + asm(shellcraft.sh())")
    else:
        next_steps.append("NX enabled - need ROP/ret2libc/ret2win instead of stack shellcode.")
        lines.append("# NX enabled - build a ROP chain (ret2win / ret2libc) instead of stack shellcode")
        lines.append("# rop = ROP(elf)")
        lines.append("# rop.call('win_function_name_here')  # if a ret2win target exists")

    if pie:
        next_steps.append("PIE enabled - you need a leaked address (a GOT/libc pointer, or a stack/heap leak) before any ROP chain addresses are usable.")
        lines.append("# PIE enabled - leak a base address before computing gadget addresses")
    else:
        next_steps.append("PIE disabled - addresses in the binary are static, gadget addresses can be hardcoded directly from the binary.")

    lines += [
        "",
        "# payload = b'A' * OFFSET + p64(TARGET_ADDR)   # fill in OFFSET from a cyclic-pattern crash",
        "io.sendline(payload)",
        "io.interactive()",
    ]

    findings.append(Finding(
        label="pwntools_skeleton",
        summary="Generated pwntools script skeleton based on detected protections",
        confidence=0.9 if checksec_output else 0.3,
        data="\n".join(lines),
    ))

    next_steps.append(
        "To find OFFSET: run with `cyclic(200)` as input, let it crash, then `cyclic_find()` the value in "
        "the crashed register/return address under gdb/pwndbg."
    )

    return AnalysisResult(
        plugin="reverse.dynamic_planner",
        category="reverse",
        findings=findings,
        tool_log=["no execution performed - this only reads the checksec output already gathered from static analysis"],
        next_steps=next_steps,
    )
