"""
Steganography / file-forensics pipeline.

This is the "upload a file, get an Aperi'Solve-style automatic run" module.
Every check shells out to a real CLI tool and captures its output - there is
no re-implementation of binwalk/steghide/etc. in Python, because the whole
point is to orchestrate the tools people already trust rather than replace
them.

Design notes:
- Every subprocess call is wrapped so a missing binary (e.g. zsteg isn't
  installed) degrades to a skipped step with a note, not a crash - the
  pipeline should never die because one optional tool is absent.
- Timeouts on every call: a hung `binwalk -e` on a hostile CTF file must
  never hang the whole analysis.
- Extraction happens into a scratch directory the caller is responsible for
  cleaning up (the FastAPI route does this in a `finally`).
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional

from ..base import AnalysisResult, Finding
from ...flag_formats import scan as scan_flags

TIMEOUT = 25  # seconds - generous for CTF file sizes, short enough to not hang the API


def _run(cmd: List[str], cwd: Optional[str] = None) -> Optional[str]:
    """Run a command, return combined stdout+stderr, or None if the binary is missing."""
    binary = cmd[0]
    if shutil.which(binary) is None:
        return None
    try:
        proc = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True,
            timeout=TIMEOUT, errors="replace",
        )
        return (proc.stdout or "") + (proc.stderr or "")
    except subprocess.TimeoutExpired:
        return f"[{binary} timed out after {TIMEOUT}s - skipped]"
    except Exception as e:
        return f"[{binary} failed to run: {e}]"


def analyze_file(filepath: str, scratch_dir: str) -> AnalysisResult:
    path = Path(filepath)
    findings: List[Finding] = []
    tool_log: List[str] = []
    next_steps: List[str] = []

    if not path.exists():
        return AnalysisResult(plugin="stego.analyzer", category="stego", error="file not found")

    ext = path.suffix.lower()

    # --- file: what actually is this, regardless of extension ---------------
    tool_log.append(f"file {path.name}")
    file_out = _run(["file", str(path)])
    if file_out:
        findings.append(Finding(label="file_type", summary=file_out.strip(), confidence=1.0))
        if "current directory" not in file_out and ext and ext.strip('.') not in file_out.lower():
            next_steps.append("The real file type may not match the extension - check for a renamed/polyglot file.")

    # --- strings: surface anything printable, scan directly for flags -------
    tool_log.append(f"strings -n 6 {path.name}")
    strings_out = _run(["strings", "-n", "6", str(path)])
    if strings_out:
        flags = scan_flags(strings_out)
        interesting = [l for l in strings_out.splitlines() if len(l) > 6][:40]
        findings.append(Finding(
            label="strings",
            summary=f"{len(strings_out.splitlines())} printable strings (showing first 40 of length>6)",
            confidence=0.6,
            data="\n".join(interesting),
            flags_found=flags,
        ))
        if flags:
            next_steps.insert(0, f"Flag pattern found directly in strings output: {flags}")

    # --- exiftool: metadata, often where CTF authors hide a hint ------------
    tool_log.append(f"exiftool {path.name}")
    exif_out = _run(["exiftool", str(path)])
    if exif_out:
        flags = scan_flags(exif_out)
        findings.append(Finding(
            label="exiftool",
            summary="Metadata extracted",
            confidence=0.7,
            data=exif_out.strip(),
            flags_found=flags,
        ))
        if "Comment" in exif_out or flags:
            next_steps.append("Check the Comment/UserComment EXIF fields closely - a common hiding spot.")

    # --- binwalk: embedded files / signatures --------------------------------
    tool_log.append(f"binwalk {path.name}")
    binwalk_out = _run(["binwalk", str(path)])
    embedded_found = False
    if binwalk_out:
        lines = [l for l in binwalk_out.splitlines() if l.strip() and not l.startswith("DECIMAL")]
        embedded_found = len(lines) > 1  # more than just the header line at offset 0's own container
        findings.append(Finding(
            label="binwalk",
            summary=f"{len(lines)} signature(s) found" if lines else "No embedded signatures found",
            confidence=0.75 if embedded_found else 0.3,
            data=binwalk_out.strip(),
        ))
        if embedded_found:
            next_steps.append("binwalk found embedded signatures - extracting automatically with `binwalk -e`.")
            extract_dir = os.path.join(scratch_dir, "binwalk_extracted")
            os.makedirs(extract_dir, exist_ok=True)
            tool_log.append(f"binwalk -e --directory={extract_dir} {path.name}")
            extract_out = _run(["binwalk", "-e", f"--directory={extract_dir}", str(path)])
            extracted_files = []
            for root, _, files in os.walk(extract_dir):
                for f in files:
                    extracted_files.append(os.path.relpath(os.path.join(root, f), extract_dir))
            if extracted_files:
                findings.append(Finding(
                    label="binwalk_extracted",
                    summary=f"Extracted {len(extracted_files)} file(s) from embedded data",
                    confidence=0.85,
                    detail={"files": extracted_files[:30]},
                ))
                next_steps.append(f"Recurse the analysis on the extracted files: {extracted_files[:5]}")

    # --- image-specific tools -------------------------------------------------
    if ext in (".png", ".bmp", ".jpg", ".jpeg", ".gif"):
        if ext == ".png":
            tool_log.append(f"pngcheck -v {path.name}")
            pngcheck_out = _run(["pngcheck", "-v", str(path)])
            if pngcheck_out:
                corrupt = "ERROR" in pngcheck_out or "CRC error" in pngcheck_out
                findings.append(Finding(
                    label="pngcheck",
                    summary="PNG structure issue detected - possible corrupted/patched chunk" if corrupt else "PNG structure looks valid",
                    confidence=0.7 if corrupt else 0.4,
                    data=pngcheck_out.strip(),
                ))
                if corrupt:
                    next_steps.append("pngcheck flagged a structural issue - check IHDR/IDAT chunk sizes, a classic 'fix the height' CTF trick.")

            tool_log.append(f"zsteg -a {path.name}")
            zsteg_out = _run(["zsteg", "-a", str(path)])
            if zsteg_out is None:
                findings.append(Finding(label="zsteg", summary="zsteg not installed in this environment (install via `gem install zsteg`)", confidence=0.0))
            elif zsteg_out.strip():
                flags = scan_flags(zsteg_out)
                findings.append(Finding(label="zsteg", summary="LSB/channel analysis results", confidence=0.65, data=zsteg_out.strip(), flags_found=flags))
                if flags:
                    next_steps.insert(0, f"zsteg surfaced a flag pattern directly: {flags}")

        # steghide: only meaningful for jpg/bmp/wav, and needs a passphrase -
        # we can only check if the file *has* embedded data with an empty
        # passphrase attempt, real cracking needs stegseek/a wordlist.
        if ext in (".jpg", ".jpeg", ".bmp"):
            tool_log.append(f"steghide info {path.name}")
            steghide_out = _run(["steghide", "info", str(path), "-p", ""])
            if steghide_out:
                embedded = "embedded" in steghide_out.lower() and "no" not in steghide_out.lower()[:80]
                findings.append(Finding(
                    label="steghide_info",
                    summary=steghide_out.strip()[:300],
                    confidence=0.5,
                ))
                next_steps.append("steghide requires a passphrase to extract - try an empty passphrase, common CTF words, or run stegseek with rockyou.txt for a real crack attempt.")

    # --- archives --------------------------------------------------------------
    if ext == ".zip":
        tool_log.append(f"zipinfo {path.name}")
        zipinfo_out = _run(["zipinfo", str(path)])
        if zipinfo_out:
            findings.append(Finding(label="zipinfo", summary="Archive contents", confidence=0.6, data=zipinfo_out.strip()))
        tool_log.append(f"unzip -l {path.name}")

    # --- QR / barcode -----------------------------------------------------------
    if ext in (".png", ".jpg", ".jpeg", ".bmp", ".gif"):
        tool_log.append(f"zbarimg {path.name}")
        zbar_out = _run(["zbarimg", "--raw", str(path)])
        if zbar_out and zbar_out.strip() and "scanned 0 barcode" not in zbar_out:
            flags = scan_flags(zbar_out)
            findings.append(Finding(label="qr_barcode", summary="QR/barcode decoded", confidence=0.9, data=zbar_out.strip(), flags_found=flags))

    # --- audio: stegsnow / spectrogram hint --------------------------------------
    if ext == ".wav":
        tool_log.append(f"steghide info {path.name}")
        steghide_out = _run(["steghide", "info", str(path), "-p", ""])
        if steghide_out:
            findings.append(Finding(label="steghide_info_wav", summary=steghide_out.strip()[:300], confidence=0.5))
        next_steps.append("For WAV files, also check the spectrogram (Sonic Visualiser / Audacity) - text/QR hidden visually in frequency data is common.")

    if ext == ".txt" or "text" in (file_out or "").lower():
        tool_log.append(f"stegsnow -C {path.name}")
        snow_out = _run(["stegsnow", "-C", str(path)])
        if snow_out is None:
            pass  # binary not installed, silently skip - not every text file needs this
        elif snow_out.strip():
            findings.append(Finding(label="stegsnow", summary="Whitespace-steganography (snow) decode attempt", confidence=0.4, data=snow_out.strip()))
            next_steps.append("stegsnow needs the right password for real content - this is an unauthenticated decode attempt only.")

    # --- flag scan across everything we've gathered so far -----------------
    all_text = "\n".join(f.data or "" for f in findings)
    direct_flags = scan_flags(all_text)
    if direct_flags:
        next_steps.insert(0, f"Combined flag scan across all tool output found: {direct_flags}")

    if not next_steps:
        next_steps.append("Nothing obviously hid itself yet. Try steghide/stegseek with rockyou.txt, or check LSB manually with a hex/bit viewer.")

    return AnalysisResult(
        plugin="stego.analyzer",
        category="stego",
        findings=findings,
        tool_log=tool_log,
        next_steps=next_steps,
    )
