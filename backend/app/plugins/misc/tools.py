"""
Misc CTF utility belt - the small stateless converters that don't deserve
their own module but get used constantly: base conversion, JWT decode (no
signature verification - this is a decoder, not a forger), timestamp
conversion, UUID parsing, unicode inspection, regex testing.
"""

from __future__ import annotations

import base64
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional


def base_convert(value: str, from_base: int, to_base: int) -> Dict[str, Any]:
    try:
        n = int(value.strip(), from_base)
    except ValueError as e:
        return {"error": f"'{value}' is not valid in base {from_base}: {e}"}

    if to_base == 10:
        result = str(n)
    elif to_base == 2:
        result = bin(n)[2:]
    elif to_base == 8:
        result = oct(n)[2:]
    elif to_base == 16:
        result = hex(n)[2:]
    else:
        digits = "0123456789abcdefghijklmnopqrstuvwxyz"
        if n == 0:
            result = "0"
        else:
            chars = []
            while n:
                n, r = divmod(n, to_base)
                chars.append(digits[r])
            result = ''.join(reversed(chars))
    return {"input": value, "from_base": from_base, "to_base": to_base, "result": result}


def decode_jwt(token: str) -> Dict[str, Any]:
    """Decode (not verify) a JWT - splits header.payload.signature and base64url-decodes each."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return {"error": "not a 3-part JWT (header.payload.signature)"}

    def b64url_decode(s: str) -> Any:
        padded = s + "=" * (-len(s) % 4)
        raw = base64.urlsafe_b64decode(padded)
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw.decode("utf-8", errors="replace")

    try:
        header = b64url_decode(parts[0])
        payload = b64url_decode(parts[1])
    except Exception as e:
        return {"error": f"failed to decode: {e}"}

    warnings = []
    if isinstance(header, dict) and header.get("alg", "").lower() == "none":
        warnings.append("alg=none - this token requires no signature at all; classic JWT auth bypass.")
    if isinstance(header, dict) and "jku" in header:
        warnings.append("jku header present - possible JWK Set URL injection vector.")
    if isinstance(header, dict) and "kid" in header:
        warnings.append("kid header present - check for kid-based SQLi/path-traversal/key-confusion attacks.")

    return {
        "header": header,
        "payload": payload,
        "signature_b64": parts[2],
        "warnings": warnings,
        "note": "signature was NOT verified - this is a decoder only.",
    }


def convert_timestamp(value: str) -> Dict[str, Any]:
    value = value.strip()
    # numeric epoch (seconds or ms)
    if re.fullmatch(r"-?\d+(\.\d+)?", value):
        num = float(value)
        if abs(num) > 10**12:  # looks like milliseconds
            num = num / 1000
        try:
            dt = datetime.fromtimestamp(num, tz=timezone.utc)
            return {"input": value, "interpreted_as": "epoch", "utc_iso": dt.isoformat()}
        except (OverflowError, OSError, ValueError) as e:
            return {"error": str(e)}
    # ISO string -> epoch
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return {"input": value, "interpreted_as": "iso8601", "epoch_seconds": dt.timestamp()}
    except ValueError:
        return {"error": "could not parse as epoch or ISO8601"}


def parse_uuid(value: str) -> Dict[str, Any]:
    try:
        u = uuid.UUID(value.strip())
    except ValueError as e:
        return {"error": str(e)}
    result = {"input": value, "version": u.version, "variant": str(u.variant), "hex": u.hex}
    if u.version == 1:
        # version 1 UUIDs embed a timestamp and MAC address - a real leak vector
        ts = (u.time - 0x01b21dd213814000) / 1e7  # 100ns intervals since UUID epoch -> seconds since Unix epoch
        try:
            result["embedded_timestamp_utc"] = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            pass
        result["embedded_node_mac_hex"] = f"{u.node:012x}"
        result["note"] = "v1 UUIDs leak a timestamp and MAC/node ID - useful for enumeration/OSINT."
    return result


def unicode_inspect(text: str) -> Dict[str, Any]:
    chars = []
    for ch in text[:200]:  # cap so a huge paste doesn't blow up the response
        chars.append({
            "char": ch,
            "codepoint": f"U+{ord(ch):04X}",
            "name": _unicode_name(ch),
            "utf8_hex": ch.encode("utf-8").hex(),
        })
    return {"length": len(text), "chars": chars}


def _unicode_name(ch: str) -> str:
    import unicodedata
    try:
        return unicodedata.name(ch)
    except ValueError:
        return "(no name)"


def regex_test(pattern: str, text: str, flags: Optional[str] = None) -> Dict[str, Any]:
    flag_val = 0
    if flags:
        for f in flags:
            flag_val |= {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}.get(f, 0)
    try:
        compiled = re.compile(pattern, flag_val)
    except re.error as e:
        return {"error": f"invalid regex: {e}"}
    matches = []
    for m in compiled.finditer(text):
        matches.append({"match": m.group(0), "start": m.start(), "end": m.end(), "groups": m.groups()})
    return {"pattern": pattern, "match_count": len(matches), "matches": matches[:100]}
