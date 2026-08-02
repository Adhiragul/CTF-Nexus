"""
Flag-format profiles.

A "profile" is what the user sets up once per CTF: the flag prefix/regex
for that event (e.g. HTB{...}, picoCTF{...}, HF2026{...}, or a fully custom
regex). Every plugin result gets scanned against the active profile(s) so a
flag surfaces the moment any tool output contains it - including partial
matches like HF2026{abc????xyz} that are worth flagging even if incomplete.

Stored in-memory + persisted to a small JSON file so profiles survive a
backend restart without needing a full database for something this small.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Optional
from uuid import uuid4

DATA_FILE = Path(__file__).parent / "data" / "flag_profiles.json"
DATA_FILE.parent.mkdir(parents=True, exist_ok=True)

# A handful of common competition formats, seeded so the dropdown isn't empty
# on first run. Users add their own (e.g. a specific college CTF's prefix).
BUILTIN_PRESETS = {
    "HTB": r"HTB\{[^}]{1,200}\}",
    "THM": r"THM\{[^}]{1,200}\}",
    "picoCTF": r"picoCTF\{[^}]{1,200}\}",
    "flag (generic)": r"flag\{[^}]{1,200}\}",
    "CTF (generic)": r"CTF\{[^}]{1,200}\}",
}


def _load() -> Dict[str, dict]:
    if DATA_FILE.exists():
        try:
            return json.loads(DATA_FILE.read_text())
        except json.JSONDecodeError:
            return {}
    return {}


def _save(data: Dict[str, dict]) -> None:
    DATA_FILE.write_text(json.dumps(data, indent=2))


def list_profiles() -> List[dict]:
    return list(_load().values())


def create_profile(name: str, prefix: Optional[str], custom_regex: Optional[str]) -> dict:
    """
    `prefix` is the simple case: user types "HF2026" and we build
    HF2026\\{...\\} automatically. `custom_regex` overrides that entirely for
    events with unusual formats.
    """
    if custom_regex:
        pattern = custom_regex
    elif prefix:
        escaped = re.escape(prefix)
        pattern = rf"{escaped}\{{[^}}]{{1,200}}\}}"
    else:
        raise ValueError("either prefix or custom_regex is required")

    # validate it actually compiles before we save it
    re.compile(pattern)

    profiles = _load()
    pid = str(uuid4())[:8]
    profiles[pid] = {"id": pid, "name": name, "pattern": pattern}
    _save(profiles)
    return profiles[pid]


def delete_profile(pid: str) -> bool:
    profiles = _load()
    if pid in profiles:
        del profiles[pid]
        _save(profiles)
        return True
    return False


def active_patterns() -> Dict[str, str]:
    """All user profiles plus the builtin presets, name -> regex pattern."""
    combined = dict(BUILTIN_PRESETS)
    for p in _load().values():
        combined[p["name"]] = p["pattern"]
    return combined


def scan(text: str) -> List[str]:
    """
    Scan arbitrary text against every active pattern (user profiles +
    builtin presets) and return every match found, deduplicated.

    Also does a lightweight "partial flag" pass: if a pattern's prefix
    (e.g. `HF2026{`) appears but the regex doesn't fully match (truncated
    output, non-printable bytes mixed in, etc.), that's still surfaced as a
    lower-confidence partial hit so it isn't missed entirely.
    """
    if not text:
        return []

    hits: List[str] = []
    for _, pattern in active_patterns().items():
        for m in re.finditer(pattern, text):
            hit = m.group(0)
            if hit not in hits:
                hits.append(hit)

        # partial: look for the literal opening brace prefix even without a
        # clean close, e.g. "HF2026{part" with no closing brace nearby
        open_prefix_match = re.match(r"^(.*?)\\\{", pattern)
        if open_prefix_match:
            literal_prefix = open_prefix_match.group(1).replace("\\", "")
            for m in re.finditer(re.escape(literal_prefix) + r"\{[^\s\"']{0,80}", text):
                hit = m.group(0)
                if hit not in hits and not hit.endswith("}"):
                    hits.append(hit + "  (partial - truncated or corrupted)")

    return hits
