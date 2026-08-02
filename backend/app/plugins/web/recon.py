"""
Web recon module.

Automates the "open robots.txt, view-source, check headers" ritual every
web CTF challenge starts with. Everything here is passive/read-only GET
requests against pages the user gives us - no fuzzing, no directory
bruteforce, no active exploitation. That line matters: this tool is for
challenges you're authorized to test (your own CTF instance), not a
scanner for arbitrary targets.
"""

from __future__ import annotations

import re
from typing import List, Optional
from urllib.parse import urljoin, urlparse

import httpx

from ..base import AnalysisResult, Finding
from ...flag_formats import scan as scan_flags

TIMEOUT = 10.0
UA = "CTF-Nexus/0.1 (authorized-testing-only)"

SENSITIVE_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version", "Via", "X-Generator",
]
SECURITY_HEADERS = [
    "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options",
    "Strict-Transport-Security", "Referrer-Policy", "Permissions-Policy",
]


def _get(client: httpx.Client, url: str) -> Optional[httpx.Response]:
    try:
        return client.get(url, timeout=TIMEOUT, follow_redirects=True)
    except httpx.HTTPError:
        return None


def analyze_url(target_url: str) -> AnalysisResult:
    findings: List[Finding] = []
    tool_log: List[str] = []
    next_steps: List[str] = []

    parsed = urlparse(target_url)
    if not parsed.scheme:
        target_url = "http://" + target_url
        parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    with httpx.Client(headers={"User-Agent": UA}, verify=False) as client:
        # --- main page: headers, source, comments ----------------------------
        tool_log.append(f"GET {target_url}")
        resp = _get(client, target_url)
        if resp is None:
            return AnalysisResult(
                plugin="web.recon", category="web",
                error=f"Could not reach {target_url} (connection failed or timed out).",
            )

        header_lines = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        findings.append(Finding(label="response_headers", summary=f"HTTP {resp.status_code}", confidence=1.0, data=header_lines))

        disclosed = {h: resp.headers[h] for h in SENSITIVE_HEADERS if h in resp.headers}
        if disclosed:
            findings.append(Finding(
                label="tech_disclosure",
                summary=f"Server discloses: {', '.join(f'{k}={v}' for k, v in disclosed.items())}",
                confidence=0.8,
                detail=disclosed,
            ))

        missing_sec = [h for h in SECURITY_HEADERS if h not in resp.headers]
        if missing_sec:
            findings.append(Finding(
                label="missing_security_headers",
                summary=f"Missing: {', '.join(missing_sec)}",
                confidence=0.5,
            ))

        if resp.cookies:
            cookie_flags = []
            for name in resp.cookies:
                cookie_flags.append(name)
            findings.append(Finding(label="cookies", summary=f"Cookies set: {', '.join(cookie_flags)}", confidence=0.6,
                                     detail={"note": "check for missing HttpOnly/Secure/SameSite flags in the raw Set-Cookie header"}))

        html = resp.text
        comments = re.findall(r"<!--(.*?)-->", html, re.DOTALL)
        comments = [c.strip() for c in comments if c.strip()]
        if comments:
            comment_text = "\n---\n".join(comments[:20])
            flags = scan_flags(comment_text)
            findings.append(Finding(label="html_comments", summary=f"{len(comments)} HTML comment(s) found", confidence=0.7, data=comment_text, flags_found=flags))
            if flags:
                next_steps.insert(0, f"Flag found directly in an HTML comment: {flags}")

        forms = re.findall(r"<form[^>]*>", html, re.IGNORECASE)
        if forms:
            findings.append(Finding(label="forms", summary=f"{len(forms)} <form> element(s) found", confidence=0.5, data="\n".join(forms)))

        js_files = list(dict.fromkeys(re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', html, re.IGNORECASE)))
        if js_files:
            findings.append(Finding(label="js_files", summary=f"{len(js_files)} JS file(s) referenced", confidence=0.6, detail={"files": js_files[:20]}))
            next_steps.append(f"Pull down and grep the referenced JS files for endpoints/keys: {js_files[:5]}")

        page_flags = scan_flags(html)
        if page_flags:
            next_steps.insert(0, f"Flag pattern found directly in page source: {page_flags}")

        # --- robots.txt -------------------------------------------------------
        robots_url = urljoin(base, "/robots.txt")
        tool_log.append(f"GET {robots_url}")
        robots_resp = _get(client, robots_url)
        if robots_resp is not None and robots_resp.status_code == 200 and robots_resp.text.strip():
            disallowed = re.findall(r"Disallow:\s*(\S+)", robots_resp.text)
            flags = scan_flags(robots_resp.text)
            findings.append(Finding(
                label="robots_txt", summary=f"robots.txt found, {len(disallowed)} Disallow entries",
                confidence=0.8, data=robots_resp.text.strip(), flags_found=flags,
            ))
            if disallowed:
                next_steps.append(f"robots.txt disallows: {disallowed[:10]} - these are the paths worth checking first.")

        # --- sitemap.xml --------------------------------------------------------
        sitemap_url = urljoin(base, "/sitemap.xml")
        tool_log.append(f"GET {sitemap_url}")
        sitemap_resp = _get(client, sitemap_url)
        if sitemap_resp is not None and sitemap_resp.status_code == 200 and "<urlset" in sitemap_resp.text:
            urls = re.findall(r"<loc>(.*?)</loc>", sitemap_resp.text)
            findings.append(Finding(label="sitemap_xml", summary=f"sitemap.xml found, {len(urls)} URL(s)", confidence=0.7, detail={"urls": urls[:30]}))

        # --- common backup/config files (passive HEAD-style GET only) ---------
        common_paths = [".git/HEAD", ".env", "backup.zip", "config.php.bak", "web.config.bak", ".DS_Store"]
        found_common = []
        for p in common_paths:
            check_url = urljoin(base, p)
            tool_log.append(f"GET {check_url}")
            r = _get(client, check_url)
            if r is not None and r.status_code == 200 and len(r.content) > 0:
                found_common.append(p)
        if found_common:
            findings.append(Finding(
                label="exposed_common_paths",
                summary=f"Accessible without auth: {', '.join(found_common)}",
                confidence=0.9,
            ))
            next_steps.append(
                f"{found_common} returned 200 - these commonly leak source/secrets (.git especially). "
                "Only proceed if you're authorized to test this target."
            )

    if not next_steps:
        next_steps.append("No obvious low-hanging fruit yet - move to manual source review, parameter fuzzing, or check for known CVEs in the disclosed tech stack.")

    return AnalysisResult(plugin="web.recon", category="web", findings=findings, tool_log=tool_log, next_steps=next_steps)
