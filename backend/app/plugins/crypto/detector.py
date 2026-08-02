"""
Crypto / hash auto-detection - the dCode/CyberChef-style "paste it and it
tells you what it is" module.

Design: every check is independent and returns 0+ Findings with a
confidence score. We run ALL checks and let the caller sort by confidence
rather than trying to short-circuit on the first match, because CTF input
is frequently layered (base64 of hex of a Caesar cipher, etc.) and the
"obviously right" answer isn't always the first one tried.
"""

from __future__ import annotations

import base64
import binascii
import math
import re
import string
from collections import Counter
from typing import List, Optional

from ..base import AnalysisResult, Finding
from ...flag_formats import scan as scan_flags

# ---------------------------------------------------------------------------
# Shared scoring helpers
# ---------------------------------------------------------------------------

_ENGLISH_FREQ = {
    'e': 12.70, 't': 9.06, 'a': 8.17, 'o': 7.51, 'i': 6.97, 'n': 6.75,
    's': 6.33, 'h': 6.09, 'r': 5.99, 'd': 4.25, 'l': 4.03, 'c': 2.78,
    'u': 2.76, 'm': 2.41, 'w': 2.36, 'f': 2.23, 'g': 2.02, 'y': 1.97,
    'p': 1.93, 'b': 1.49, 'v': 0.98, 'k': 0.77, 'j': 0.15, 'x': 0.15,
    'q': 0.10, 'z': 0.07,
}
_COMMON_WORDS = {
    "the", "flag", "is", "you", "this", "and", "for", "are", "with",
    "ctf", "password", "secret", "key", "admin", "user", "open", "sesame",
}


def english_score(text: str) -> float:
    """
    0..1 heuristic: how plausible is this English/printable text.
    Combines letter-frequency chi-square-ish distance with a bonus for
    common CTF/English words and a penalty for non-printable bytes.
    """
    if not text:
        return 0.0

    printable_ratio = sum(1 for c in text if c in string.printable) / len(text)
    if printable_ratio < 0.85:
        return printable_ratio * 0.3  # almost certainly not decoded text

    letters = [c.lower() for c in text if c.isalpha()]
    if not letters:
        return printable_ratio * 0.4

    counts = Counter(letters)
    total = len(letters)
    diff = 0.0
    for ch, expected_pct in _ENGLISH_FREQ.items():
        observed_pct = (counts.get(ch, 0) / total) * 100
        diff += abs(observed_pct - expected_pct)
    # diff of 0 = perfect match to English letter frequency; scale it down
    freq_score = max(0.0, 1 - (diff / 300))

    lowered = text.lower()
    word_hits = sum(1 for w in _COMMON_WORDS if w in lowered)
    word_bonus = min(0.3, word_hits * 0.08)

    return min(1.0, 0.6 * freq_score + 0.3 * printable_ratio + word_bonus)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


# ---------------------------------------------------------------------------
# Hash identification
# ---------------------------------------------------------------------------

# (name, exact-length regex, hashcat mode, john format, notes)
_HASH_SIGNATURES = [
    ("MD5 / NTLM",       r"^[a-fA-F0-9]{32}$",  "0 (MD5) or 1000 (NTLM)", "Raw-MD5 / NT",  "Ambiguous: MD5 and NTLM are both 32 hex chars. Context (Windows dump vs generic) usually disambiguates."),
    ("MySQL323",         r"^[a-fA-F0-9]{16}$",  "200",                     "mysql",         "Old MySQL < 4.1 password hash."),
    ("CRC32",            r"^[a-fA-F0-9]{8}$",   "n/a (checksum, not a hash)", "n/a",        "8 hex chars is a very generic pattern (could just as easily be hex-encoded ASCII) - low confidence unless context (e.g. a .zip/.png CRC field) supports it."),
    ("SHA1",              r"^[a-fA-F0-9]{40}$",  "100",                     "Raw-SHA1",      ""),
    ("SHA224",             r"^[a-fA-F0-9]{56}$",  "1300",                    "Raw-SHA224",    ""),
    ("SHA256",             r"^[a-fA-F0-9]{64}$",  "1400",                    "Raw-SHA256",    ""),
    ("SHA384",             r"^[a-fA-F0-9]{96}$",  "10800",                   "Raw-SHA384",    ""),
    ("SHA512",             r"^[a-fA-F0-9]{128}$", "1700",                    "Raw-SHA512",    ""),
    ("bcrypt",             r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$", "3200", "bcrypt", ""),
    ("MD5 crypt (Unix)",  r"^\$1\$[./A-Za-z0-9]{0,8}\$[./A-Za-z0-9]{22}$", "500", "md5crypt", ""),
    ("sha256crypt (Unix)", r"^\$5\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{43}$", "7400", "sha256crypt", ""),
    ("sha512crypt (Unix)", r"^\$6\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{86}$", "1800", "sha512crypt", ""),
    ("NTLMv2 (net-ntlmv2)", r"^.+::.+:[a-fA-F0-9]{16}:[a-fA-F0-9]+:[a-fA-F0-9]+$", "5600", "netntlmv2", ""),
]


def identify_hash(text: str) -> List[Finding]:
    stripped = text.strip()
    findings = []
    for name, pattern, hashcat, john, note in _HASH_SIGNATURES:
        if re.match(pattern, stripped):
            difficulty = "low" if "MD5" in name or "SHA1" == name else "medium"
            if name in ("CRC32", "MySQL323"):
                confidence = 0.25  # short generic hex patterns are ambiguous with plain hex-encoded text
            elif "/" in name:
                confidence = 0.6
            else:
                confidence = 0.85
            findings.append(Finding(
                label=f"hash:{name}",
                summary=f"Looks like {name}",
                confidence=confidence,
                detail={
                    "hashcat_mode": hashcat,
                    "john_format": john,
                    "crack_difficulty_estimate": difficulty,
                    "note": note,
                },
            ))
    return findings


# ---------------------------------------------------------------------------
# Encoding detection (each returns a Finding if it looks plausible)
# ---------------------------------------------------------------------------

def try_base64(text: str) -> Optional[Finding]:
    s = text.strip()
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", s) or len(s) % 4 != 0 or len(s) < 4:
        return None
    try:
        decoded = base64.b64decode(s, validate=True)
        try:
            as_text = decoded.decode("utf-8")
        except UnicodeDecodeError:
            as_text = None
        score = english_score(as_text) if as_text else 0.3
        return Finding(
            label="base64",
            summary="Valid Base64",
            confidence=max(0.55, score),
            data=as_text if as_text else decoded.hex(),
            detail={"decoded_as": "text" if as_text else "hex (binary output)"},
        )
    except (binascii.Error, ValueError):
        return None


def try_base32(text: str) -> Optional[Finding]:
    s = text.strip().upper()
    if not re.fullmatch(r"[A-Z2-7]+=*", s) or len(s) < 8:
        return None
    try:
        decoded = base64.b32decode(s)
        as_text = decoded.decode("utf-8", errors="ignore")
        score = english_score(as_text)
        if score < 0.25:
            return None
        return Finding(label="base32", summary="Valid Base32", confidence=score, data=as_text)
    except (binascii.Error, ValueError):
        return None


def try_base85(text: str) -> Optional[Finding]:
    s = text.strip()
    if len(s) < 5:
        return None
    try:
        decoded = base64.b85decode(s)
        as_text = decoded.decode("utf-8", errors="ignore")
        score = english_score(as_text)
        if score < 0.25:
            return None
        return Finding(label="base85", summary="Valid Base85/ASCII85", confidence=score, data=as_text)
    except (ValueError,):
        return None


_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def try_base58(text: str) -> Optional[Finding]:
    s = text.strip()
    if not s or any(c not in _B58_ALPHABET for c in s) or len(s) < 6:
        return None
    try:
        num = 0
        for ch in s:
            num = num * 58 + _B58_ALPHABET.index(ch)
        decoded = num.to_bytes((num.bit_length() + 7) // 8, "big")
        as_text = decoded.decode("utf-8", errors="ignore")
        score = english_score(as_text)
        return Finding(label="base58", summary="Decodable as Base58", confidence=min(score, 0.5), data=as_text)
    except Exception:
        return None


def try_hex(text: str) -> Optional[Finding]:
    s = re.sub(r"\s|0x", "", text.strip())
    if not re.fullmatch(r"[A-Fa-f0-9]+", s) or len(s) < 4 or len(s) % 2 != 0:
        return None
    if set(s) <= {"0", "1"} and len(s) % 8 == 0:
        return None  # pure 0/1 string of byte-aligned length - treat as binary, not hex
    try:
        decoded = bytes.fromhex(s)
        as_text = decoded.decode("utf-8", errors="ignore")
        score = english_score(as_text)
        return Finding(
            label="hex",
            summary="Valid hexadecimal",
            confidence=max(0.5, score),
            data=as_text if score > 0.3 else decoded.hex(),
            detail={"decoded_as": "text" if score > 0.3 else "non-printable bytes (shown re-encoded as hex)"},
        )
    except ValueError:
        return None


def try_binary(text: str) -> Optional[Finding]:
    s = re.sub(r"\s", "", text.strip())
    if not re.fullmatch(r"[01]+", s) or len(s) < 8 or len(s) % 8 != 0:
        return None
    try:
        n = int(s, 2)
        decoded = n.to_bytes(len(s) // 8, "big")
        as_text = decoded.decode("utf-8", errors="ignore")
        score = english_score(as_text)
        return Finding(label="binary", summary="Binary (8-bit groups)", confidence=max(0.65, score + 0.1), data=as_text)
    except (ValueError, OverflowError):
        return None


def try_url_encoding(text: str) -> Optional[Finding]:
    if "%" not in text or not re.search(r"%[0-9A-Fa-f]{2}", text):
        return None
    import urllib.parse
    decoded = urllib.parse.unquote(text)
    if decoded == text:
        return None
    return Finding(label="url_encoding", summary="URL/percent-encoded", confidence=0.8, data=decoded)


def try_html_entities(text: str) -> Optional[Finding]:
    if "&" not in text or not re.search(r"&#?\w+;", text):
        return None
    import html
    decoded = html.unescape(text)
    if decoded == text:
        return None
    return Finding(label="html_entities", summary="HTML entity-encoded", confidence=0.75, data=decoded)


def try_morse(text: str) -> Optional[Finding]:
    s = text.strip()
    if not re.fullmatch(r"[.\-/ \n]+", s) or "." not in s and "-" not in s:
        return None
    table = {
        '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F',
        '--.': 'G', '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
        '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R',
        '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
        '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
        '...--': '3', '....-': '4', '.....': '5', '-....': '6', '--...': '7',
        '---..': '8', '----.': '9',
    }
    words = s.split('/')
    out = []
    for word in words:
        letters = word.split()
        out.append(''.join(table.get(l, '?') for l in letters))
    decoded = ' '.join(out).strip()
    if not decoded or decoded.count('?') > len(decoded) * 0.3:
        return None
    return Finding(label="morse", summary="Morse code", confidence=0.85, data=decoded)


def try_bacon(text: str) -> Optional[Finding]:
    """Bacon cipher: 24/26-letter variant using A/B in blocks of 5."""
    stripped_input = text.strip()
    non_space = re.sub(r"\s", "", stripped_input)
    if not non_space:
        return None
    s = re.sub(r"[^ABab]", "", stripped_input)
    # guard: the input must actually BE an A/B sequence, not just contain
    # some a/b letters buried in unrelated prose
    if len(s) / len(non_space) < 0.95:
        return None
    if len(s) < 10 or len(s) % 5 != 0:
        return None
    bacon_table = {}
    letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    for i, ch in enumerate(letters):
        code = format(i, '05b').replace('0', 'A').replace('1', 'B')
        bacon_table[code] = ch
    chunks = [s[i:i + 5].upper() for i in range(0, len(s), 5)]
    decoded = ''.join(bacon_table.get(c, '?') for c in chunks)
    if decoded.count('?') > len(decoded) * 0.3:
        return None
    return Finding(label="bacon_cipher", summary="Bacon cipher (A/B, blocks of 5)", confidence=0.55, data=decoded)


# ---------------------------------------------------------------------------
# Classical cipher bruteforce
# ---------------------------------------------------------------------------

def _looks_like_cipher_prose(text: str) -> bool:
    """
    Classical letter ciphers (Caesar/ROT/Atbash/Rail fence) operate on prose-
    like ciphertext - letters and spaces/punctuation, not the digit- and
    symbol-heavy alphabets of base64/hex/binary. Without this guard those
    checks fire constantly on encoded blobs and drown out the real answer.
    """
    s = text.strip()
    if not s:
        return False
    letters = sum(1 for c in s if c.isalpha())
    digits = sum(1 for c in s if c.isdigit())
    symbols = sum(1 for c in s if c in "+/=_%&;")
    if letters / len(s) < 0.7:
        return False
    if digits > 0 or symbols > 0:
        return False
    return True


def caesar_shift(text: str, shift: int) -> str:
    out = []
    for ch in text:
        if ch.isupper():
            out.append(chr((ord(ch) - 65 + shift) % 26 + 65))
        elif ch.islower():
            out.append(chr((ord(ch) - 97 + shift) % 26 + 97))
        else:
            out.append(ch)
    return ''.join(out)


def try_caesar_rot(text: str) -> Optional[Finding]:
    if not _looks_like_cipher_prose(text):
        return None
    baseline = english_score(text)
    best_shift, best_score, best_text = 0, -1.0, text
    for shift in range(1, 26):
        candidate = caesar_shift(text, shift)
        score = english_score(candidate)
        if score > best_score:
            best_shift, best_score, best_text = shift, score, candidate
    if best_score < 0.35 or best_score - baseline < 0.15:
        return None
    label = "rot13" if best_shift == 13 else f"caesar_shift_{best_shift}"
    return Finding(
        label=label,
        summary=f"Caesar cipher, best fit at shift {best_shift}" + (" (ROT13)" if best_shift == 13 else ""),
        confidence=min(0.95, best_score + 0.1),
        data=best_text,
        detail={"shift": best_shift},
    )


def try_atbash(text: str) -> Optional[Finding]:
    if not _looks_like_cipher_prose(text):
        return None
    out = []
    for ch in text:
        if ch.isupper():
            out.append(chr(90 - (ord(ch) - 65)))
        elif ch.islower():
            out.append(chr(122 - (ord(ch) - 97)))
        else:
            out.append(ch)
    decoded = ''.join(out)
    score = english_score(decoded)
    baseline = english_score(text)
    if score < 0.35 or score - baseline < 0.15:
        return None
    return Finding(label="atbash", summary="Atbash cipher", confidence=score, data=decoded)


def try_rail_fence(text: str) -> Optional[Finding]:
    if not _looks_like_cipher_prose(text):
        return None
    s = re.sub(r"\s", "", text)
    if len(s) < 6:
        return None
    best = None
    for rails in range(2, 7):
        try:
            decoded = _rail_fence_decode(s, rails)
        except Exception:
            continue
        score = english_score(decoded)
        if best is None or score > best[1]:
            best = (decoded, score, rails)
    baseline = english_score(text)
    if not best or best[1] < 0.4 or best[1] - baseline < 0.15:
        return None
    decoded, score, rails = best
    return Finding(
        label="rail_fence",
        summary=f"Rail fence cipher, best fit at {rails} rails",
        confidence=score,
        data=decoded,
        detail={"rails": rails},
    )


def _rail_fence_decode(text: str, rails: int) -> str:
    fence = [[] for _ in range(rails)]
    pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
    idx_cycle = [pattern[i % len(pattern)] for i in range(len(text))]
    counts = Counter(idx_cycle)
    pos = 0
    rail_chars = {}
    for r in range(rails):
        rail_chars[r] = list(text[pos:pos + counts[r]])
        pos += counts[r]
    result = []
    rail_pointers = {r: 0 for r in range(rails)}
    for r in idx_cycle:
        result.append(rail_chars[r][rail_pointers[r]])
        rail_pointers[r] += 1
    return ''.join(result)


def try_xor_single_byte(text: str) -> Optional[Finding]:
    """Only meaningful on hex-looking input; brute-forces all 256 single-byte keys."""
    s = re.sub(r"\s|0x", "", text.strip())
    if not re.fullmatch(r"[A-Fa-f0-9]+", s) or len(s) < 6 or len(s) % 2 != 0:
        return None
    if set(s) <= {"0", "1"} and len(s) % 8 == 0:
        return None  # pure 0/1 string - binary, not hex
    try:
        raw = bytes.fromhex(s)
    except ValueError:
        return None
    best_key, best_score, best_text = None, -1.0, None
    for key in range(256):
        candidate = bytes(b ^ key for b in raw)
        try:
            candidate_text = candidate.decode("utf-8")
        except UnicodeDecodeError:
            continue
        score = english_score(candidate_text)
        if score > best_score:
            best_key, best_score, best_text = key, score, candidate_text
    if best_score < 0.45:
        return None
    return Finding(
        label="xor_single_byte",
        summary=f"Single-byte XOR, best key 0x{best_key:02x}",
        confidence=best_score * 0.85,
        data=best_text,
        detail={"key_hex": f"0x{best_key:02x}", "key_dec": best_key},
    )


def try_polybius(text: str) -> Optional[Finding]:
    s = re.sub(r"[^1-5\s]", "", text.strip())
    digits = s.replace(" ", "")
    if len(digits) < 4 or len(digits) % 2 != 0 or not digits:
        return None
    # standard 5x5 (I/J combined)
    grid = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    out = []
    for i in range(0, len(digits), 2):
        row, col = int(digits[i]) - 1, int(digits[i + 1]) - 1
        if not (0 <= row < 5 and 0 <= col < 5):
            return None
        out.append(grid[row * 5 + col])
    decoded = ''.join(out)
    return Finding(label="polybius", summary="Polybius square (5x5, I/J combined)", confidence=0.45, data=decoded)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

CHECKS = [
    try_base64, try_base32, try_base85, try_base58, try_hex, try_binary,
    try_url_encoding, try_html_entities, try_morse, try_bacon,
    try_caesar_rot, try_atbash, try_rail_fence, try_xor_single_byte,
    try_polybius,
]


def analyze_crypto(text: str) -> AnalysisResult:
    text = text.strip()
    findings: List[Finding] = []
    tool_log = ["identify_hash()"]

    findings.extend(identify_hash(text))

    for check in CHECKS:
        tool_log.append(f"{check.__name__}()")
        try:
            result = check(text)
        except Exception:
            result = None
        if result:
            findings.append(result)

    # entropy on the raw bytes, useful to flag "this is probably encrypted/
    # compressed, not just encoded" when everything scores low
    raw_bytes = text.encode("utf-8", errors="ignore")
    entropy = shannon_entropy(raw_bytes)
    if not findings and entropy > 4.0:
        findings.append(Finding(
            label="high_entropy",
            summary=f"No encoding/cipher matched. Entropy {entropy:.2f} bits/byte is high - likely encrypted, compressed, or a raw hash/key.",
            confidence=0.3,
            detail={"entropy": round(entropy, 3)},
        ))

    # flag scan every decoded value plus the raw input
    for f in findings:
        if f.data:
            f.flags_found = scan_flags(f.data)
    direct_flags = scan_flags(text)

    findings.sort(key=lambda f: f.confidence, reverse=True)

    next_steps = []
    if findings:
        top = findings[0]
        if top.label.startswith("hash:"):
            next_steps.append(f"Try hashcat mode {top.detail.get('hashcat_mode')} against rockyou.txt")
        elif top.label == "base64" and top.data and re.fullmatch(r"[A-Za-z0-9+/=]+", top.data or ""):
            next_steps.append("Output still looks encoded - feed it back through the detector (nested encoding is common).")
        elif top.confidence < 0.5:
            next_steps.append("Low confidence overall - try dCode's cipher identifier or CyberChef's Magic wand operation for a second opinion.")
    else:
        next_steps.append("Nothing matched. If this came from a binary/file, check entropy and consider it may be AES/RSA ciphertext (identify only, can't auto-decrypt without a key).")

    if direct_flags:
        next_steps.insert(0, f"Flag pattern matched directly in the raw input: {direct_flags}")

    return AnalysisResult(
        plugin="crypto.detector",
        category="crypto",
        findings=findings,
        tool_log=tool_log,
        next_steps=next_steps,
    )
