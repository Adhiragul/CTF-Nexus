# CTF Nexus

A CTF copilot that automates the repetitive first-pass analysis every
challenge starts with: paste-to-detect crypto/hashes, upload-to-analyze
stego files, and a one-click web recon pass — with a flag-format profile
that highlights matches (including partial/truncated ones) the instant any
module finds them, across whatever prefix your college/event uses
(`HF2026{}`, `HTB{}`, custom regex, etc).

Built incrementally and **actually tested at every step** — not just
written and hoped to work. See "What's real vs. scaffolded" below for an
honest breakdown.

## Quick start

### Option A — Docker (recommended, gets you every CLI tool for free)
```bash
docker compose up --build
```
- Frontend: http://localhost:3000
- Backend API: http://localhost:8000 (interactive docs at `/docs`)

### Option B — run locally without Docker
```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```
Then open `frontend/index.html` directly in a browser (it points at
`localhost:8000` automatically).

**Local-mode caveat:** the stego and forensics modules shell out to real CLI
tools (`file`, `strings`, `exiftool`, `binwalk`, `steghide`, `foremost`,
`pngcheck`, `zbarimg`, `stegsnow`, `zsteg`, `tshark`, `checksec`). Install
what you don't have:
```bash
# Debian/Ubuntu/Kali
sudo apt install file binutils exiftool binwalk steghide foremost pngcheck zbar-tools tshark checksec
sudo gem install zsteg
```
`tshark` may ask an interactive "allow non-root users to capture packets"
question on first install - answer however you like, it doesn't affect
reading existing .pcap files, only live capture (which this tool never does).

Any tool that isn't installed is skipped gracefully (you'll see a
0-confidence finding noting it's missing) rather than crashing the pipeline.

## What's real vs. scaffolded

| Module | Status |
|---|---|
| **Crypto/Hash** | Working. Hash ID (MD5/SHA1/224/256/384/512/bcrypt/crypt formats) with hashcat+john mappings, Base64/32/58/85/hex/binary/URL/HTML/Morse/Bacon auto-decode, Caesar/ROT13/Atbash/Rail-fence/single-byte-XOR/Polybius brute-force with English-scoring confidence, entropy fallback. |
| **Stego** | Working. Real subprocess pipeline: file → strings → exiftool → binwalk (+auto-extraction) → pngcheck/zsteg (PNG) → steghide info (jpg/bmp) → zipinfo → zbarimg (QR/barcode) → stegsnow (text). Tested against a crafted PNG with an appended flag and an EXIF-comment flag — both caught. |
| **Web Recon** | Working. robots.txt, sitemap.xml, response headers, security-header gaps, cookies, HTML comments, JS file scraping, common exposed paths (`.git/HEAD`, `.env`, etc.) — passive GETs only, no active exploitation. |
| **Forensics / PCAP** | Working. Real `tshark` pipeline: capinfos summary, protocol hierarchy, TCP conversation table, every TCP stream reconstructed + flag-scanned, HTTP object export (auto-extracted + flag-scanned), cleartext credential detection (HTTP Basic Auth, FTP USER/PASS), DNS-exfiltration heuristics (long/high-entropy subdomains), raw-payload flag scan for non-stream (UDP) traffic. Tested against a crafted PCAP with HTTP creds + a flag + a DNS exfil pattern. |
| **Reverse Engineering** | Static triage (file/strings-for-keywords/readelf/checksec) **plus** two new pieces: a decompiled-C analyzer (paste Ghidra/r2/Binja pseudocode → flags `strcmp`/`memcmp` literal checks, dangerous functions, XOR/encoding loops, hardcoded byte arrays, suspicious function names like `win()`) and a dynamic-analysis planner (reads `checksec` JSON output, auto-generates a pwntools skeleton + a plain-English exploit plan based on canary/NX/PIE). Binary upload auto-chains straight into the dynamic plan. **No actual execution of uploaded binaries** — that's a deliberate safety line, see below. **No Ghidra headless/disassembly integration yet** — you still run Ghidra yourself and paste the output in. |
| **Misc tools** | Working. Base converter, JWT decoder (flags `alg:none`/`kid`/`jku`), timestamp converter, UUID parser (extracts embedded MAC+timestamp from v1 UUIDs), unicode inspector, regex tester. |
| **Flag profiles** | Working. Built-in presets (HTB/THM/picoCTF/generic) + custom prefix or regex, persisted to disk, scanned against every module's output automatically. |
| **OSINT** | Not built. Design notes in `backend/app/plugins/NOT_YET_BUILT.md` — needs a decision on which lookup APIs to wire in before writing code (rate limits, keys, ToS). |

## Architecture

```
backend/app/
  plugins/
    base.py          # Plugin/Finding/AnalysisResult contracts
    crypto/detector.py
    stego/analyzer.py
    web/recon.py
    forensics/pcap_analyzer.py
    reverse/analyzer.py           # static triage
    reverse/decompiled_analyzer.py  # decompiled-C patterns + dynamic-analysis planner
    misc/tools.py
    NOT_YET_BUILT.md      # OSINT design notes
  routers/            # FastAPI routes, one per category
  flag_formats.py      # profile storage + scanning, shared by every module
  main.py              # app wiring
frontend/
  index.html / style.css / app.js   # no build step, plain JS + fetch
```

Adding a new tool to an existing module (e.g. another stego check) means
adding one function to that module's analyzer and appending it to the
pipeline — the router and frontend don't need to change. Adding a whole new
category means following the same four-file pattern (`plugins/x/analyzer.py`
→ `routers/x.py` → `main.py` include → a new tab in `index.html`/`app.js`).

## Security notes

- The web recon module only ever does passive `GET` requests — it doesn't
  fuzz directories, doesn't brute-force, doesn't exploit anything. Point it
  only at targets you own or are authorized to test.
- Stego file uploads are capped at 50MB and analyzed in an isolated scratch
  directory per session; nothing is executed from inside the uploaded file
  itself (no auto-run of extracted binaries).
- Uploaded binaries in the Reverse module are **never executed** - only
  read by static tools (`file`, `strings`, `readelf`, `checksec`). The
  "dynamic analysis" feature only ever generates a pwntools script
  *template* for you to run yourself, deliberately, on your own machine -
  CTF binaries are untrusted by definition and auto-running them would be
  a real RCE risk in an automated tool.
- CORS is wide open (`*`) because this is meant to run on `localhost` for a
  single user during a competition — don't deploy this to the public
  internet as-is.

## Roadmap (suggested build order for what's left)

1. **Ghidra headless integration** for the reverse module — turns "paste
   the pseudocode yourself" into a fully automated decompile step.
2. **WHOIS/DNS OSINT** — lower-hanging fruit than social-profile
   correlation, no API-key decisions needed to get started.
3. Memory-dump / disk-image forensics (Volatility3 / Sleuthkit) — heaviest
   tooling, least frequently the bottleneck in a typical CTF.
4. Everything else in `NOT_YET_BUILT.md`.
