# Forensics & OSINT modules - not yet built

These two are intentionally left as empty plugin packages (`plugins/forensics/`,
`plugins/osint/`) rather than half-working stubs, because both need design
decisions before writing throwaway code:

## Forensics (PCAP / memory dumps / disk images)
- PCAP: wrap `tshark -r file.pcap -Y <filter>` for protocol breakdown, then
  `tshark --export-objects http,/tmp/out` to pull files out of HTTP streams -
  this is the single highest-value forensics feature for CTFs (DNS
  exfiltration, credentials in cleartext protocols, extracted files).
- Memory dumps: Volatility 3 (`vol3 -f dump.mem windows.pslist`, etc.) needs
  a profile/symbol table step first - plan for a "detect OS" pass before
  running plugins.
- Disk images: `sleuthkit`/`tsk_recover` is already installed in this sandbox's
  apt tree (pulled in as a binwalk dependency) and is a reasonable starting
  point for `fls`/`icat` based extraction.

## OSINT (username / email / domain / IP)
- WHOIS/DNS: `whois` + `dig`/`dnspython` for A/MX/TXT/subdomain enumeration.
- Username -> social profile correlation needs either Sherlock (MIT-licensed,
  vendored as a subprocess call) or a maintained API - many free lookup APIs
  used by similar tools rate-limit or require a key, so this needs a
  decision on which paid/free services to wire in before writing the calls.
- Breach-status lookups (HaveIBeenPwned-style) need an API key and have
  usage terms worth reading before automating - don't wire this up as an
  unauthenticated bulk-query tool.

Both follow the same pattern as `stego/analyzer.py` and `reverse/analyzer.py`:
a `analyze_*(...)` function returning `AnalysisResult`, wired into a router,
wired into the frontend. Build order suggestion: PCAP forensics first (most
reusable across CTF categories), then WHOIS/DNS OSINT, then memory/disk
forensics last (heaviest tooling, least frequently the bottleneck).
