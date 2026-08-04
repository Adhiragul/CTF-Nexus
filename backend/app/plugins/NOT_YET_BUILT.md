# OSINT module (and deeper forensics) - not yet built

`plugins/osint/` is intentionally left as an empty plugin package rather
than a half-working stub, because it needs a couple of decisions before
writing throwaway code:

## OSINT (username / email / domain / IP)
- WHOIS/DNS: `whois` + `dig`/`dnspython` for A/MX/TXT/subdomain enumeration -
  the lowest-effort, highest-value starting point, no API keys needed.
- Username -> social profile correlation needs either Sherlock (MIT-licensed,
  vendored as a subprocess call) or a maintained API - many free lookup APIs
  used by similar tools rate-limit or require a key, so this needs a
  decision on which paid/free services to wire in before writing the calls.
- Breach-status lookups (HaveIBeenPwned-style) need an API key and have
  usage terms worth reading before automating - don't wire this up as an
  unauthenticated bulk-query tool.

## Deeper forensics (memory dumps / disk images)
PCAP analysis is done (`plugins/forensics/pcap_analyzer.py`). Still open:
- Memory dumps: Volatility 3 (`vol3 -f dump.mem windows.pslist`, etc.) needs
  a profile/symbol table step first - plan for a "detect OS" pass before
  running plugins.
- Disk images: `sleuthkit`/`tsk_recover` is a reasonable starting point for
  `fls`/`icat`-based file extraction.

## Deeper reverse engineering (real decompilation)
`plugins/reverse/decompiled_analyzer.py` analyzes pseudocode you already
produced with Ghidra/r2/Binja - it doesn't decompile anything itself yet.
A real integration means:
- Ghidra headless: `analyzeHeadless <project> <name> -import <binary> -postScript <script>`
  where the post-script dumps every function's decompiled C to a text file,
  then feeding that straight into `analyze_decompiled_code()`. Needs Ghidra
  installed (~300MB Java app) and a Jython/Java post-script - the biggest
  lift of everything listed here.
- radare2/r2pipe is a lighter-weight alternative if full Ghidra automation
  is overkill - `r2 -q -c 'aaa; pdgj @@f' binary` dumps decompiled JSON per
  function directly from Python via r2pipe.

Each of these follows the same pattern as everything else in `plugins/`: an
`analyze_*(...)` function returning `AnalysisResult`, wired into a router,
wired into the frontend. Suggested build order: WHOIS/DNS OSINT first (no
API-key decisions needed), then Ghidra/r2 automation, then memory/disk
forensics last (heaviest tooling, least frequently the bottleneck).
