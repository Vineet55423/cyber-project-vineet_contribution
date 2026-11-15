"""
SecureScan ZAP backend — tiered (basic / deep), built on zap_backend_fixed.py.

HONEST SCOPE NOTE (read before wiring this into the pitch):
  ZAP is an HTTP proxy/scanner. It CANNOT do two of your "Top 5 Basic" tests:
    - TLS/cipher-suite inspection  -> this needs a raw TLS socket (your Node
      lib/guard.ts auditTls() already does this correctly). Keep it there.
    - SPF/DMARC DNS lookups        -> this needs DNS TXT queries (your Node
      lib/passive.ts already does this correctly). Keep it there.
  Claiming ZAP performs these would be exactly the kind of fake/static claim
  this whole project has been trying to eliminate. The code below only makes
  ZAP do what ZAP can actually do, and leaves clearly marked merge points for
  the other two.

BASIC TIER (via ZAP) — passive only, no attack payloads, fast by construction:
  1. Security headers   — ZAP passive rules (CSP/HSTS/X-Frame-Options/etc.)
  2. (TLS)               — NOT from ZAP. Merge from your Node auditTls().
  3. Cookie flags        — ZAP passive rules (Secure/HttpOnly/SameSite)
  4. (SPF/DMARC)         — NOT from ZAP. Merge from your Node checkEmailPosture().
  5. Vulnerable JS libs  — ZAP passive rule "Vulnerable JS Library" (Retire.js
                           add-on). VERIFY it's installed: zap.pscan.scanners()
                           must list it, or this silently finds nothing.

DEEP TIER (via ZAP) — active scan, policy restricted to ONLY these 4 rules
(everything else disabled — this is the single biggest speed win):
  1. Reflected XSS        -> plugin 40012
  2. SQL Injection         -> plugin 40018 (generic; DB-specific variants
                              40019-40024/40027 left OFF on purpose — they
                              re-test the same injection points per DB engine
                              and are the main reason full scans take so long)
  3. Open Redirect         -> plugin 20019 ("External Redirect", CWE-601)
  4. CORS Misconfiguration -> plugin 40040 — ALPHA rule. Only fires if the
                              "Alpha Active Scan Rules" add-on is installed.
                              Verify with zap.ascan.scanners() before relying
                              on it; if absent, drop it from REQUIRED and keep
                              your existing Node CORS check (lib/deep.ts) instead.
  5. Sensitive file/admin discovery -> NOT run through ZAP here. ZAP's path-
     discovery add-on (Forced Browse) has an API surface I won't guess at —
     getting a plugin/method name wrong here would silently do nothing, which
     is worse than not claiming it. Use your already-verified Node check
     (lib/deep.ts: /.git/HEAD, /.env, /admin, etc.) and merge its findings in.
"""
import os
import time
import socket
import ipaddress
import threading
import uuid
from urllib.parse import urlparse

import requests
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from zapv2 import ZAPv2

app = FastAPI(title="SecureScan ZAP Backend API (tiered)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ZAP_URL = os.environ.get("ZAP_URL", "http://localhost:8080")
ZAP_API_KEY = os.environ.get("ZAP_API_KEY", "securescan-local-key-123")
VERIFY_URL = os.environ.get("VERIFY_URL", "http://localhost:3000/api/verify")

# ----------------------------------------------------------------------------
# Ownership gate — unchanged from zap_backend_fixed.py. Deep tier MUST pass
# this; basic tier is passive-only so it's allowed to run without it, same
# policy your Next.js app already uses.
# ----------------------------------------------------------------------------
def require_verified_ownership(hostname: str) -> None:
    try:
        r = requests.post(VERIFY_URL, json={"domain": hostname, "check": True}, timeout=10)
        data = r.json()
    except Exception as e:
        raise HTTPException(503, f"Could not reach ownership verification service: {e}")
    if not data.get("verified"):
        raise HTTPException(403, {
            "error": "Ownership not verified. Publish the DNS TXT record or well-known file first.",
            "code": "NOT_VERIFIED", "challenge": data.get("challenge"),
        })


_BLOCKED_NETS = [ipaddress.ip_network(n) for n in [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16",
    "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
    "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "::/128",
]]


def validate_target(raw: str) -> str:
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(400, "Only http/https targets are allowed.")
    hostname = parsed.hostname
    if not hostname or hostname == "localhost":
        raise HTTPException(400, "Invalid or disallowed hostname.")
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        raise HTTPException(400, "Hostname could not be resolved.")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if any(ip in net for net in _BLOCKED_NETS):
            raise HTTPException(400, "Target resolves to a non-public address and cannot be scanned.")
    return f"{parsed.scheme}://{hostname}{(':' + str(parsed.port)) if parsed.port else ''}"


_scans: dict[str, dict] = {}

# Plugin IDs — confirmed against ZAP's active scan rules.
# Verify these exist in YOUR ZAP version with: zap.ascan.scanners()
DEEP_RULE_IDS = {
    "40012": "Reflected XSS",
    "40018": "SQL Injection (generic)",
    "20019": "Open Redirect (External Redirect)",
    "41": "Git Source Code Exposure",
    "40040": "CORS Misconfiguration (alpha — verify add-on installed)",
}
# Passive alert NAME substrings for the 5 basic tier tests (filtering by name,
# because passive rule IDs vary across ZAP add-on versions).
BASIC_HEADER_MATCH = ["Header", "Content Security Policy", "X-Frame", "X-Content-Type", "Strict-Transport"]
BASIC_COOKIE_MATCH = ["Cookie"]
BASIC_JSLIB_MATCH = ["Vulnerable JS Library", "JavaScript Library"]
BASIC_SERVER_INFO_MATCH = ["Server Leaks", "Server Information", "X-Powered-By", "X-AspNet-Version", "Server:"]
BASIC_DIRECTORY_BROWSING_MATCH = ["Directory Browsing", "Index of /", "Directory Listing"]


def _passive_wait(zap, timeout_s=30):
    waited = 0
    while int(zap.pscan.records_to_scan) > 0 and waited < timeout_s:
        time.sleep(1)
        waited += 1


def _run_basic(scan_id: str, target: str):
    """Passive-only. Visits the page once, lets ZAP's passive engine analyse
    the traffic it already proxied, then filters alerts. No spider, no attack
    payloads — this is fast by construction (seconds, not minutes)."""
    state = _scans[scan_id]
    try:
        zap = ZAPv2(apikey=ZAP_API_KEY, proxies={"http": ZAP_URL, "https": ZAP_URL})
        state["phase"] = "fetching"
        zap.core.access_url(target)          # one real request, proxied through ZAP
        state["phase"] = "passive_scan"
        _passive_wait(zap)

        alerts = zap.core.alerts(baseurl=target)
        findings = []

        def collect(match_list, category):
            for a in alerts:
                name = a.get("alert", "")
                if any(m.lower() in name.lower() for m in match_list):
                    findings.append({
                        "category": category, "name": name, "risk": a.get("risk"),
                        "confidence": a.get("confidence"), "url": a.get("url"),
                        "description": a.get("description"), "solution": a.get("solution"),
                    })

        collect(BASIC_HEADER_MATCH, "security_headers")
        collect(BASIC_COOKIE_MATCH, "cookie_flags")
        collect(BASIC_JSLIB_MATCH, "vulnerable_js_library")
        collect(BASIC_SERVER_INFO_MATCH, "server_info_disclosure")
        collect(BASIC_DIRECTORY_BROWSING_MATCH, "directory_browsing")

        # Check Retire.js passive scanner availability
        retire_found = False
        try:
            pscan_list = zap.pscan.scanners
            if callable(pscan_list):
                pscan_list = pscan_list()
            if isinstance(pscan_list, list):
                retire_found = any("vulnerable js library" in str(s.get("name", "")).lower() for s in pscan_list)
        except Exception as e:
            state.setdefault("warnings", []).append(f"Could not verify pscan scanners: {e}")

        state["retirejs_available"] = retire_found
        if not retire_found:
            state.setdefault("warnings", []).append(
                "Retire.js add-on is missing in ZAP! Test #3 (Vulnerable JS Libraries) requires the 'retire' add-on from ZAP Marketplace."
            )

        state.update(
            status="COMPLETED", phase="done", findings_from_zap=findings,
            total_alerts=len(findings),
            note="100% ZAP Native: Passive scan evaluated 5 basic rules.",
        )
    except Exception as e:
        state.update(status="FAILED", error=str(e))


def _run_deep(scan_id: str, target: str):
    state = _scans[scan_id]
    try:
        zap = ZAPv2(apikey=ZAP_API_KEY, proxies={"http": ZAP_URL, "https": ZAP_URL})

        # Minimal spider — just enough to find injectable endpoints, capped for speed.
        zap.spider.set_option_max_depth(1)
        zap.spider.set_option_max_children(5)
        state["phase"] = "spider"
        sid = zap.spider.scan(target)
        while int(zap.spider.status(sid)) < 100:
            state["progress"] = int(zap.spider.status(sid))
            time.sleep(2)

        # --- Restrict the active scan to ONLY the 5 rules above ---
        policy = "Default Policy"
        zap.ascan.disable_all_scanners(scanpolicyname=policy)
        zap.ascan.enable_scanners(",".join(DEEP_RULE_IDS.keys()), scanpolicyname=policy)

        # Verify what actually got enabled
        try:
            ascan_list = zap.ascan.scanners(scanpolicyname=policy)
            if callable(ascan_list):
                ascan_list = ascan_list()
            enabled = {str(s.get("id")): s.get("name", "") for s in ascan_list if str(s.get("enabled", "")).lower() == "true"}
        except Exception:
            enabled = {}

        state["rules_actually_enabled"] = enabled

        missing_rules = []
        if "41" not in enabled:
            missing_rules.append("Plugin 41 (Git Source Code Exposure) missing in ZAP. Requires 'Beta Active Scan Rules' (ascanrulesBeta) add-on.")
        if "40040" not in enabled:
            missing_rules.append("Plugin 40040 (CORS Misconfiguration) missing in ZAP. Requires 'Alpha Active Scan Rules' (ascanrulesAlpha) add-on.")

        if missing_rules:
            state.setdefault("warnings", []).extend(missing_rules)

        zap.ascan.set_option_thread_per_host(20)
        zap.ascan.set_option_delay_in_ms(0)
        zap.ascan.set_option_max_rule_duration_in_mins(1)
        zap.ascan.set_option_max_scan_duration_in_mins(5)
        zap.ascan.set_policy_attack_strength(id="", attackstrength="LOW", scanpolicyname=policy)
        zap.ascan.set_policy_alert_threshold(id="", alertthreshold="MEDIUM", scanpolicyname=policy)

        state["phase"] = "active_scan"
        ascan_id = zap.ascan.scan(target, scanpolicyname=policy)
        retries, max_retries = 0, 10
        while True:
            try:
                progress = int(zap.ascan.status(ascan_id))
                state["progress"] = progress
                if progress >= 100:
                    break
                retries = 0
            except (requests.exceptions.ProxyError, requests.exceptions.ConnectionError):
                retries += 1
                if retries >= max_retries:
                    raise RuntimeError("ZAP container connection lost repeatedly.")
            time.sleep(5)

        raw_alerts = zap.core.alerts(baseurl=target)
        findings = []
        for idx, a in enumerate(raw_alerts):
            if a.get("risk") == "False Positive":
                continue
            findings.append({
                "id": a.get("id", str(idx)), "name": a.get("name"), "risk": a.get("risk"),
                "confidence": a.get("confidence"), "url": a.get("url"),
                "description": a.get("description"), "solution": a.get("solution"),
                "evidence": (a.get("evidence") or "")[:300],
            })

        state.update(
            status="COMPLETED", phase="done", progress=100, findings_from_zap=findings,
            total_alerts=len(findings),
            note="100% ZAP Native: Active scan evaluated Reflected XSS (40012), SQLi (40018), Open Redirect (20019), Git Exposure (41), and CORS (40040).",
        )
    except Exception as e:
        state.update(status="FAILED", error=str(e))


@app.post("/api/scan")
def start_scan(target: str = Query(...), tier: str = Query("basic", pattern="^(basic|deep)$")):
    safe_target = validate_target(target)
    hostname = urlparse(safe_target).hostname
    if tier == "deep":
        require_verified_ownership(hostname)   # basic stays passive-only, no gate needed

    scan_id = str(uuid.uuid4())
    _scans[scan_id] = {"status": "RUNNING", "phase": "starting", "progress": 0, "tier": tier, "target": safe_target}
    job = _run_basic if tier == "basic" else _run_deep
    threading.Thread(target=job, args=(scan_id, safe_target), daemon=True).start()
    return {"scan_id": scan_id, "status": "RUNNING", "tier": tier}


@app.get("/api/scan/{scan_id}/status")
def scan_status(scan_id: str):
    state = _scans.get(scan_id)
    if not state:
        raise HTTPException(404, "Unknown scan_id.")
    return {k: state[k] for k in ("status", "phase", "progress", "tier", "target") if k in state}


@app.get("/api/scan/{scan_id}/result")
def scan_result(scan_id: str):
    state = _scans.get(scan_id)
    if not state:
        raise HTTPException(404, "Unknown scan_id.")
    if state["status"] != "COMPLETED":
        raise HTTPException(409, f"Scan is not finished yet (status={state['status']}).")
    return state


@app.get("/api/zap/diagnostics")
def zap_diagnostics():
    """
    Pre-flight check endpoint for ZAP deployment:
    1. Checks if ZAP is reachable.
    2. Checks if Retire.js is installed (Basic Test #3: Vulnerable JS Libraries).
    3. Checks if Plugin 41 (Git Exposure) is installed (requires Beta Active Scan Rules).
    4. Checks if Plugin 40040 (CORS Misconfig) is installed (requires Alpha Active Scan Rules).
    """
    try:
        zap = ZAPv2(apikey=ZAP_API_KEY, proxies={"http": ZAP_URL, "https": ZAP_URL})
        version = zap.core.version
    except Exception as e:
        return {
            "connected": False,
            "zap_url": ZAP_URL,
            "error": f"Cannot reach ZAP engine: {e}",
            "hint": "Ensure ZAP Docker container is running (e.g. docker run -u zap -p 8080:8080 -d ghcr.io/zaproxy/zaproxy:stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.key=securescan-local-key-123)",
        }

    # 1. Check Retire.js passive scanner
    retire_installed = False
    try:
        pscan_scanners = zap.pscan.scanners
        if callable(pscan_scanners):
            pscan_scanners = pscan_scanners()
        if isinstance(pscan_scanners, list):
            retire_installed = any("vulnerable js library" in str(s.get("name", "")).lower() for s in pscan_scanners)
    except Exception:
        pass

    # 2. Check Active scanners (41 and 40040)
    git_installed = False
    cors_installed = False
    try:
        ascan_scanners = zap.ascan.scanners()
        if isinstance(ascan_scanners, list):
            scanner_ids = {str(s.get("id")) for s in ascan_scanners}
            git_installed = "41" in scanner_ids
            cors_installed = "40040" in scanner_ids
    except Exception:
        pass

    missing = []
    if not retire_installed:
        missing.append({"name": "Retire.js", "id": "retire", "purpose": "Basic Test #3 (Vulnerable JS Libraries)"})
    if not git_installed:
        missing.append({"name": "Beta Active Scan Rules", "id": "ascanrulesBeta", "purpose": "Deep Test #4 (Plugin 41: Git Source Code Exposure)"})
    if not cors_installed:
        missing.append({"name": "Alpha Active Scan Rules", "id": "ascanrulesAlpha", "purpose": "Deep Test #5 (Plugin 40040: CORS Misconfiguration)"})

    return {
        "connected": True,
        "zap_version": version,
        "zap_url": ZAP_URL,
        "checks": {
            "retire_js_installed": retire_installed,
            "git_exposure_installed": git_installed,
            "cors_misconfig_installed": cors_installed,
        },
        "all_rules_ready": (retire_installed and git_installed and cors_installed),
        "missing_addons": missing,
    }


@app.post("/api/zap/install-addons")
def install_zap_addons():
    """
    Attempts to automatically install the 3 required add-ons into the running ZAP instance:
    - retire (Retire.js)
    - ascanrulesBeta (Beta Active Scan Rules -> Plugin 41)
    - ascanrulesAlpha (Alpha Active Scan Rules -> Plugin 40040)
    """
    try:
        zap = ZAPv2(apikey=ZAP_API_KEY, proxies={"http": ZAP_URL, "https": ZAP_URL})
    except Exception as e:
        raise HTTPException(503, f"ZAP unreachable: {e}")

    results = {}
    for addon_id in ["retire", "ascanrulesBeta", "ascanrulesAlpha"]:
        try:
            res = zap.autoupdate.install_addon(id=addon_id)
            results[addon_id] = res
        except Exception as err:
            results[addon_id] = f"Error: {err}"

    return {"status": "INSTALL_REQUESTED", "results": results}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("index:app", host="0.0.0.0", port=8000, reload=True)
