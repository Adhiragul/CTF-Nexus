"""
PCAP / network-forensics module.

The core CTF workflow this automates: open a .pcap, and instead of manually
clicking through Wireshark's Follow Stream / Export Objects / protocol
hierarchy menus, get all of it at once - every TCP conversation
reconstructed and flag-scanned, every HTTP object pulled out, every DNS
query checked for exfiltration-shaped patterns (long/high-entropy
subdomains), and cleartext credentials from legacy protocols (HTTP Basic
Auth, FTP, Telnet) surfaced directly.

Everything shells out to `tshark` (Wireshark's CLI) rather than
re-implementing packet parsing - tshark's dissectors are the real, battle
-tested thing.
"""

from __future__ import annotations

import math
import os
import re
import shutil
import subprocess
from collections import Counter
from pathlib import Path
from typing import List, Optional

from ..base import AnalysisResult, Finding
from ...flag_formats import scan as scan_flags

TIMEOUT = 30


def _run(cmd: List[str]) -> Optional[str]:
    if shutil.which(cmd[0]) is None:
        return None
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT, errors="replace")
        # tshark prints a "running as root" warning to stderr on every single
        # invocation when run as root (common in Docker/CI) - it isn't useful
        # output and pollutes anything that parses stdout+stderr together, so
        # stdout is returned alone; stderr is only appended if stdout was empty
        # (i.e. the command actually failed and stderr is the only signal).
        if proc.stdout.strip():
            return proc.stdout
        return proc.stderr
    except subprocess.TimeoutExpired:
        return f"[{cmd[0]} timed out after {TIMEOUT}s]"
    except Exception as e:
        return f"[{cmd[0]} failed: {e}]"


def _subdomain_entropy(label: str) -> float:
    if not label:
        return 0.0
    counts = Counter(label)
    length = len(label)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def analyze_pcap(filepath: str, scratch_dir: str) -> AnalysisResult:
    path = Path(filepath)
    findings: List[Finding] = []
    tool_log: List[str] = []
    next_steps: List[str] = []

    if not path.exists():
        return AnalysisResult(plugin="forensics.pcap", category="forensics", error="file not found")

    if shutil.which("tshark") is None:
        return AnalysisResult(
            plugin="forensics.pcap", category="forensics",
            error="tshark not installed. `sudo apt install tshark` (Debian/Ubuntu/Kali) or `sudo gem`/brew equivalent, then retry.",
        )

    # --- capinfos: basic sanity/summary --------------------------------------
    tool_log.append(f"capinfos {path.name}")
    capinfos_out = _run(["capinfos", str(path)])
    if capinfos_out:
        findings.append(Finding(label="capture_summary", summary="Capture file summary", confidence=1.0, data=capinfos_out.strip()))

    # --- protocol hierarchy ----------------------------------------------------
    tool_log.append(f"tshark -r {path.name} -q -z io,phs")
    phs_out = _run(["tshark", "-r", str(path), "-q", "-z", "io,phs"])
    if phs_out:
        protocols = re.findall(r"^\s*(\w[\w.]*)\s+frames:(\d+)", phs_out, re.MULTILINE)
        findings.append(Finding(
            label="protocol_hierarchy",
            summary=f"{len(protocols)} protocol layer(s) seen: {', '.join(p[0] for p in protocols[:10])}",
            confidence=0.9,
            data=phs_out.strip(),
        ))

    # --- TCP/UDP conversation summary ------------------------------------------
    tool_log.append(f"tshark -r {path.name} -q -z conv,tcp")
    conv_out = _run(["tshark", "-r", str(path), "-q", "-z", "conv,tcp"])
    if conv_out and conv_out.strip():
        findings.append(Finding(label="tcp_conversations", summary="TCP conversation summary", confidence=0.6, data=conv_out.strip()))

    # --- reconstruct every TCP stream, flag-scan each one ----------------------
    stream_ids_out = _run(["tshark", "-r", str(path), "-T", "fields", "-e", "tcp.stream"])
    stream_ids = sorted(set(int(s) for s in (stream_ids_out or "").split() if s.strip().isdigit()))
    tool_log.append(f"tshark -r {path.name} -z follow,tcp,ascii,<N>  (for each of {len(stream_ids)} stream(s))")

    all_stream_flags = []
    credential_hits = []
    for sid in stream_ids[:30]:  # cap so a huge pcap doesn't hang the request
        stream_out = _run(["tshark", "-r", str(path), "-q", "-z", f"follow,tcp,ascii,{sid}"])
        if not stream_out:
            continue
        # strip the tshark banner/header lines, keep just the conversation body
        body_start = stream_out.find("===================================================================\n", 1)
        body = stream_out[body_start:] if body_start != -1 else stream_out

        flags = scan_flags(body)
        if flags:
            all_stream_flags.extend(f for f in flags if f not in all_stream_flags)
            findings.append(Finding(
                label=f"tcp_stream_{sid}",
                summary=f"TCP stream {sid} - flag pattern found in reconstructed conversation",
                confidence=0.95,
                data=body.strip()[:3000],
                flags_found=flags,
            ))
        elif re.search(r"(HTTP/1\.[01]|^GET |^POST |^USER |^PASS |Authorization:)", body, re.MULTILINE):
            # only keep bodies that look like something worth showing (HTTP/FTP-ish),
            # skip pure binary/uninteresting streams to keep the response small
            findings.append(Finding(label=f"tcp_stream_{sid}", summary=f"TCP stream {sid} (HTTP/FTP-like)", confidence=0.4, data=body.strip()[:2000]))

        auth_match = re.search(r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", body)
        if auth_match:
            import base64
            try:
                decoded_cred = base64.b64decode(auth_match.group(1)).decode("utf-8", errors="replace")
            except Exception:
                decoded_cred = "(failed to decode)"
            credential_hits.append(f"stream {sid}: HTTP Basic Auth -> {decoded_cred}")
        user_match = re.search(r"^USER\s+(\S+)", body, re.MULTILINE)
        pass_match = re.search(r"^PASS\s+(\S+)", body, re.MULTILINE)
        if user_match or pass_match:
            credential_hits.append(f"stream {sid}: FTP credentials -> USER={user_match.group(1) if user_match else '?'} PASS={pass_match.group(1) if pass_match else '?'}")

    if credential_hits:
        findings.append(Finding(
            label="cleartext_credentials",
            summary=f"{len(credential_hits)} cleartext credential(s) found in unencrypted protocols",
            confidence=0.95,
            data="\n".join(credential_hits),
        ))
        next_steps.insert(0, f"Cleartext credentials recovered: {credential_hits}")

    if all_stream_flags:
        next_steps.insert(0, f"Flag(s) found directly in TCP stream content: {all_stream_flags}")

    # --- HTTP object export -------------------------------------------------------
    http_export_dir = os.path.join(scratch_dir, "http_objects")
    os.makedirs(http_export_dir, exist_ok=True)
    tool_log.append(f"tshark -r {path.name} --export-objects http,{http_export_dir}")
    _run(["tshark", "-r", str(path), "--export-objects", f"http,{http_export_dir}"])
    exported = []
    for root, _, files in os.walk(http_export_dir):
        for f in files:
            exported.append(os.path.relpath(os.path.join(root, f), http_export_dir))
    if exported:
        # flag-scan every exported object's content directly
        export_flags = []
        for rel in exported:
            try:
                content = Path(http_export_dir, rel).read_text(errors="ignore")
                export_flags.extend(f for f in scan_flags(content) if f not in export_flags)
            except Exception:
                pass
        findings.append(Finding(
            label="http_exported_objects",
            summary=f"{len(exported)} HTTP object(s) extracted (images, files, pages transferred over HTTP)",
            confidence=0.85,
            detail={"files": exported[:30]},
            flags_found=export_flags,
        ))
        if export_flags:
            next_steps.insert(0, f"Flag found inside an HTTP-exported object: {export_flags}")
        else:
            next_steps.append(f"Inspect the exported HTTP objects directly - {exported[:5]} - especially images (check for embedded stego).")

    # --- DNS: list queries, flag suspicious high-entropy/long subdomains (exfil) --
    tool_log.append(f"tshark -r {path.name} -Y dns.flags.response==0 -T fields -e dns.qry.name")
    dns_out = _run(["tshark", "-r", str(path), "-Y", "dns.flags.response==0", "-T", "fields", "-e", "dns.qry.name"])
    if dns_out and dns_out.strip():
        queries = [q for q in dns_out.splitlines() if q.strip()]
        unique_queries = list(dict.fromkeys(queries))
        suspicious = []
        for q in unique_queries:
            label = q.split(".")[0]
            if len(label) > 25 or _subdomain_entropy(label) > 3.8:
                suspicious.append(q)
        findings.append(Finding(
            label="dns_queries",
            summary=f"{len(unique_queries)} unique DNS quer(y/ies)" + (f", {len(suspicious)} look suspicious (long/high-entropy subdomain - possible DNS exfiltration)" if suspicious else ""),
            confidence=0.8 if suspicious else 0.4,
            data="\n".join(unique_queries[:50]),
            detail={"suspicious": suspicious[:20]},
        ))
        if suspicious:
            next_steps.append(
                f"{len(suspicious)} DNS quer(y/ies) have unusually long/high-entropy subdomains: {suspicious[:5]} - "
                "classic DNS-exfiltration shape. Try concatenating the subdomain labels in query order and decoding as hex/base32."
            )
        combined_dns_flags = scan_flags("\n".join(unique_queries))
        if combined_dns_flags:
            next_steps.insert(0, f"Flag pattern found directly in a DNS query name: {combined_dns_flags}")

    # --- overall strings-style pass on the whole capture (payload bytes only) ----
    tool_log.append(f"tshark -r {path.name} -T fields -e data.data")
    payload_out = _run(["tshark", "-r", str(path), "-T", "fields", "-e", "data.data"])
    if payload_out:
        try:
            hex_blobs = [l for l in payload_out.splitlines() if l.strip()]
            decoded_chunks = []
            for blob in hex_blobs[:200]:
                try:
                    decoded_chunks.append(bytes.fromhex(blob.replace(":", "")).decode("utf-8", errors="ignore"))
                except ValueError:
                    continue
            combined = "\n".join(decoded_chunks)
            payload_flags = scan_flags(combined)
            if payload_flags:
                findings.append(Finding(
                    label="raw_payload_flag_scan",
                    summary="Flag pattern found scanning raw packet payload bytes directly",
                    confidence=0.9,
                    flags_found=payload_flags,
                ))
                next_steps.insert(0, f"Flag found in raw payload bytes (may be outside a reconstructed stream, e.g. UDP): {payload_flags}")
        except Exception:
            pass

    if not next_steps:
        next_steps.append("Nothing obvious yet - check protocol hierarchy for unexpected protocols, or try filtering to specific conversations manually in Wireshark for deeper inspection.")

    return AnalysisResult(plugin="forensics.pcap", category="forensics", findings=findings, tool_log=tool_log, next_steps=next_steps)
