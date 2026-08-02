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

**Local-mode caveat:** the stego module shells out to real CLI tools
(`file`, `strings`, `exiftool`, `binwalk`, `steghide`, `foremost`,
`pngcheck`, `zbarimg`, `stegsnow`, `zsteg`). Install what you don't have:
```bash
# Debian/Ubuntu/Kali
sudo apt install file binutils exiftool binwalk steghide foremost pngcheck zbar-tools
sudo gem install zsteg
```
Any tool that isn't installed is skipped gracefully (you'll see a
0-confidence finding noting it's missing) rather than crashing the pipeline.

## What's real vs. scaffolded

| Module | Status |
|---|---|
| **Crypto/Hash** | Working. Hash ID (MD5/SHA1/224/256/384/512/bcrypt/crypt formats) with hashcat+john mappings, Base64/32/58/85/hex/binary/URL/HTML/Morse/Bacon auto-decode, Caesar/ROT13/Atbash/Rail-fence/single-byte-XOR/Polybius brute-force with English-scoring confidence, entropy fallback. |
| **Stego** | Working. Real subprocess pipeline: file → strings → exiftool → binwalk (+auto-extraction) → pngcheck/zsteg (PNG) → steghide info (jpg/bmp) → zipinfo → zbarimg (QR/barcode) → stegsnow (text). Tested against a crafted PNG with an appended flag and an EXIF-comment flag — both caught. |
| **Web Recon** | Working. robots.txt, sitemap.xml, response headers, security-header gaps, cookies, HTML comments, JS file scraping, common exposed paths (`.git/HEAD`, `.env`, etc.) — passive GETs only, no active exploitation. |
| **Misc tools** | Working. Base converter, JWT decoder (flags `alg:none`/`kid`/`jku`), timestamp converter, UUID parser (extracts embedded MAC+timestamp from v1 UUIDs), unicode inspector, regex tester. |
| **Flag profiles** | Working. Built-in presets (HTB/THM/picoCTF/generic) + custom prefix or regex, persisted to disk, scanned against every module's output automatically. |
| **Reverse Engineering** | Static triage only (file/strings-for-keywords/readelf/checksec if installed). **No disassembly/decompilation yet** — that needs a Ghidra headless-analyzer or radare2 integration, intentionally not built until you decide how deep to go. |
| **Forensics (PCAP/memory/disk)** | Not built. Design notes in `backend/app/plugins/NOT_YET_BUILT.md` — PCAP via tshark is the recommended starting point, highest value-to-effort ratio. |
| **OSINT** | Not built. Same file has notes — needs a decision on which lookup APIs to wire in before writing code (rate limits, keys, ToS). |

## Architecture

```
backend/app/
  plugins/
    base.py          # Plugin/Finding/AnalysisResult contracts
    crypto/detector.py
    stego/analyzer.py
    web/recon.py
    misc/tools.py
    reverse/analyzer.py   # static triage only
    NOT_YET_BUILT.md      # forensics + osint design notes
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
- CORS is wide open (`*`) because this is meant to run on `localhost` for a
  single user during a competition — don't deploy this to the public
  internet as-is.

## Roadmap (suggested build order for what's left)

1. **PCAP forensics** via `tshark` — highest value, reusable across
   categories (DNS exfil, cleartext creds, HTTP object extraction).
2. **Ghidra headless integration** for the reverse module — turns static
   triage into real decompilation.
3. **WHOIS/DNS OSINT** — lower-hanging fruit than social-profile
   correlation, no API-key decisions needed to get started.
4. Everything else in `NOT_YET_BUILT.md`.
