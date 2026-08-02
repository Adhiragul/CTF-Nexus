"""
Reverse Engineering module - SCAFFOLDING ONLY.

This runs the easy, always-safe static triage (file/strings/checksec-style
flags) that works the same way on every ELF/PE regardless of what's inside.
It deliberately does NOT attempt disassembly, decompilation, or emulation -
that's Ghidra/radare2/angr territory and needs either a heavier Docker
image or an actual Ghidra headless-analyzer integration, which is the next
thing to build here.

To extend: add objdump/readelf/nm/rabin2 calls the same way stego/analyzer.py
calls its tools, then register a route in routers/ once it's real.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import List, Optional

from ..base import AnalysisResult, Finding

TIMEOUT = 20


def _run(cmd: List[str]) -> Optional[str]:
    if shutil.which(cmd[0]) is None:
        return None
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT, errors="replace")
        return (proc.stdout or "") + (proc.stderr or "")
    except Exception as e:
        return f"[{cmd[0]} failed: {e}]"


def analyze_binary(filepath: str) -> AnalysisResult:
    path = Path(filepath)
    findings: List[Finding] = []
    tool_log: List[str] = []
    next_steps = [
        "This module currently only does static triage. For a real crackme/pwn "
        "challenge, load the binary into Ghidra (or radare2 `r2 -A`) for decompilation - "
        "that integration isn't wired up yet.",
    ]

    file_out = _run(["file", str(path)])
    if file_out:
        findings.append(Finding(label="file_type", summary=file_out.strip(), confidence=1.0))

    strings_out = _run(["strings", "-n", "6", str(path)])
    if strings_out:
        interesting_keywords = ["flag", "password", "win", "system", "strcmp", "secret", "key"]
        hits = [l for l in strings_out.splitlines() if any(k in l.lower() for k in interesting_keywords)]
        findings.append(Finding(
            label="strings_of_interest",
            summary=f"{len(hits)} string(s) matched common CTF keywords",
            confidence=0.6,
            data="\n".join(hits[:40]),
        ))
        if any("win" in l.lower() for l in hits):
            next_steps.insert(0, "A 'win'-like symbol/string was found - check for a classic ret2win challenge (look for a function you can jump to directly).")

    if shutil.which("readelf"):
        readelf_out = _run(["readelf", "-h", str(path)])
        if readelf_out:
            findings.append(Finding(label="readelf_header", summary="ELF header", confidence=0.7, data=readelf_out.strip()))

    if shutil.which("checksec"):
        checksec_out = _run(["checksec", "--file=" + str(path)])
        if checksec_out:
            findings.append(Finding(label="checksec", summary="Binary protections", confidence=0.8, data=checksec_out.strip()))
    else:
        findings.append(Finding(label="checksec", summary="checksec not installed (pip install checksec.py or apt install checksec)", confidence=0.0))

    return AnalysisResult(plugin="reverse.analyzer (stub)", category="reverse", findings=findings, tool_log=tool_log, next_steps=next_steps)
