import ipaddress
import socket
import threading
import time
from urllib.parse import urlparse

import requests
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from zapv2 import ZAPv2

app = FastAPI(title="CyberShield OWASP ZAP Scanner API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ZAP_URL = "http://localhost:8080"
ZAP_API_KEY = "securescan-local-key-123"
SCAN_LOCK = threading.Lock()
SPIDER_TIMEOUT_SECONDS = 180
ACTIVE_TIMEOUT_SECONDS = 600
PASSIVE_TIMEOUT_SECONDS = 120
ADDON_BY_RULE = {
    "10003": "retire",
    "10063": "pscanrulesBeta",
    "41": "ascanrulesBeta",
    "40040": "ascanrulesBeta",
}

# Each entry is one user-facing test group. Several native ZAP rules may back
# one group (for example, the six headers in Basic test 1).
BASIC_TESTS = [
    {
        "id": "basic-security-headers",
        "name": "Missing security headers",
        "description": "Checks CSP, HSTS, clickjacking protection, MIME sniffing protection, Referrer-Policy, and Permissions-Policy.",
        "plugin_ids": ["10038", "10035", "10020", "10021", "10063"],
        "matches": ("content-security-policy", "strict-transport-security", "hsts", "clickjacking", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy"),
        "headers": ["content-security-policy", "strict-transport-security", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy"],
    },
    {
        "id": "basic-cookie-flags",
        "name": "Cookie flags and session isolation",
        "description": "Checks cookies for Secure, HttpOnly, and a safe SameSite setting.",
        "plugin_ids": ["10010", "10011", "10054"],
        "matches": ("cookie", "samesite", "httponly", "secure flag"),
    },
    {
        "id": "basic-vulnerable-javascript",
        "name": "Vulnerable JavaScript libraries",
        "description": "Checks JavaScript libraries against ZAP Retire.js vulnerability data.",
        "plugin_ids": ["10003"],
        "matches": ("vulnerable js library", "retire.js"),
    },
    {
        "id": "basic-version-disclosure",
        "name": "Server and version information disclosure",
        "description": "Checks response headers for server, framework, and runtime version details.",
        "plugin_ids": ["10036", "10037", "10061", "20020"],
        "matches": ("server leaks", "x-powered-by", "x-aspnet-version", "version with known vulnerabilities", "version information"),
    },
    {
        "id": "basic-directory-browsing",
        "name": "Exposed directory browsing",
        "description": "Checks whether a response exposes a browsable list of files and folders.",
        "plugin_ids": ["10033"],
        "matches": ("directory browsing", "directory listing", "index of /"),
    },
]

DEEP_TESTS = [
    {"id": "deep-reflected-xss", "name": "Reflected cross-site scripting (XSS)", "description": "Checks whether input sent in a request is returned as executable content in a page.", "plugin_ids": ["40012"], "matches": ("cross site scripting (reflected)", "cross-site scripting (reflected)")},
    {"id": "deep-sql-injection", "name": "SQL injection", "description": "Checks whether database input can be altered through specially formed request values.", "plugin_ids": ["40018"], "matches": ("sql injection",)},
    {"id": "deep-open-redirect", "name": "Open redirect", "description": "Checks whether a redirect parameter can send visitors to an untrusted external site.", "plugin_ids": ["20019"], "matches": ("external redirect",)},
    {"id": "deep-git-exposure", "name": "Git source code exposure", "description": "Checks whether Git repository metadata or source files are publicly accessible.", "plugin_ids": ["41"], "matches": ("source code disclosure - git", "git exposure")},
    {"id": "deep-cors", "name": "CORS misconfiguration", "description": "Checks whether the site trusts unsafe cross-origin requests from other websites.", "plugin_ids": ["40040"], "matches": ("cors misconfiguration", "cors header")},
]


class ScanRequest(BaseModel):
    target: str
    tier: str = "basic"
    attested: bool = False


def normalized_target(raw_target: str) -> str:
    target = raw_target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="Enter a website address to scan.")
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
        raise HTTPException(status_code=400, detail="Enter a valid HTTP or HTTPS website address.")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        address = None
    if address and not address.is_global:
        raise HTTPException(status_code=400, detail="Private and local IP addresses cannot be scanned.")
    if not address:
        try:
            resolved = {ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(parsed.hostname, None)}
        except socket.gaierror:
            raise HTTPException(status_code=400, detail="The website address could not be resolved.")
        if not resolved or any(not ip.is_global for ip in resolved):
            raise HTTPException(status_code=400, detail="Website addresses that resolve to private or local IPs cannot be scanned.")
    return target.rstrip("/")


def scanner_ids(scanners):
    return {
        str(scanner.get("id")).split("-")[0]
        for scanner in scanners
        if scanner.get("id") is not None
    }


def require_scanners(zap, tests, scanner_type):
    scanners = zap.pscan.scanners if scanner_type == "passive" else zap.ascan.scanners()
    available = scanner_ids(scanners)
    required = {plugin_id for test in tests for plugin_id in test["plugin_ids"]}
    missing = sorted(required - available)
    if missing:
        installed_addons = {str(addon.get("id")) for addon in zap.autoupdate.installed_addons}
        needed_addons = {ADDON_BY_RULE[rule_id] for rule_id in missing if rule_id in ADDON_BY_RULE}
        for addon_id in sorted(needed_addons - installed_addons):
            try:
                zap.autoupdate.install_addon(addon_id)
            except Exception as exc:
                raise HTTPException(status_code=503, detail=f"Could not install required ZAP add-on {addon_id}: {exc}") from exc
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            scanners = zap.pscan.scanners if scanner_type == "passive" else zap.ascan.scanners()
            available = scanner_ids(scanners)
            missing = sorted(required - available)
            if not missing:
                break
            time.sleep(2)
    if missing:
        raise HTTPException(
            status_code=503,
            detail=f"OWASP ZAP is missing required {scanner_type} scan rules: {', '.join(missing)}. Update the ZAP add-ons and retry.",
        )
    return available


def alert_plugin_id(alert):
    return str(alert.get("pluginId") or alert.get("pluginid") or "").split("-")[0]


def alert_matches_test(alert, test):
    name = str(alert.get("name") or "").lower()
    plugin_id = alert_plugin_id(alert)
    return plugin_id in test["plugin_ids"] or any(part in name for part in test["matches"])


def build_test_results(tests, alerts, missing_headers=None):
    results = []
    for test in tests:
        matched = [alert for alert in alerts if alert_matches_test(alert, test)]
        evidence = []
        if matched:
            evidence.extend(dict.fromkeys(str(alert.get("name") or "Potential issue found") for alert in matched))
        if test["id"] == "basic-security-headers" and missing_headers:
            evidence.append("Missing response headers: " + ", ".join(missing_headers))
        status = "FAIL" if evidence else "PASS"
        if test["id"] == "basic-security-headers" and missing_headers is None and not evidence:
            status = "NOT_RUN"
            evidence.append("The root response could not be read through ZAP.")
        results.append({
            "id": test["id"],
            "name": test["name"],
            "description": test["description"],
            "status": status,
            "alert_count": len(matched),
            "evidence": evidence,
            "plugin_ids": test["plugin_ids"],
        })
    return results


def wait_for_scan(status_call, scan_id, timeout_seconds, label):
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            if int(status_call(scan_id)) >= 100:
                return
        except (requests.exceptions.ProxyError, requests.exceptions.ConnectionError):
            time.sleep(2)
            continue
        time.sleep(2)
    raise HTTPException(status_code=504, detail=f"The ZAP {label} did not finish before the timeout.")


def wait_for_passive_scan(zap):
    deadline = time.monotonic() + PASSIVE_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if int(zap.pscan.records_to_scan) == 0:
            return
        time.sleep(1)
    raise HTTPException(status_code=504, detail="ZAP passive scanning did not finish before the timeout.")


def read_headers_through_zap(target):
    try:
        response = requests.get(
            target,
            proxies={"http": ZAP_URL, "https": ZAP_URL},
            verify=False,
            timeout=20,
            allow_redirects=False,
        )
        return {key.lower(): value for key, value in response.headers.items()}
    except requests.RequestException:
        return None


@app.post("/api/alerts")
def run_zap_scan(body: ScanRequest):
    tier = body.tier.lower().strip()
    if tier not in ("basic", "deep"):
        raise HTTPException(status_code=400, detail="Scan type must be basic or deep.")
    if tier == "deep" and not body.attested:
        raise HTTPException(status_code=403, detail="Deep scans require explicit authorization attestation.")
    target = normalized_target(body.target)

    if not SCAN_LOCK.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="Another ZAP scan is already running. Wait for it to finish and retry.")

    try:
        try:
            zap = ZAPv2(apikey=ZAP_API_KEY, proxies={"http": ZAP_URL, "https": ZAP_URL})
            version = zap.core.version
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"Cannot connect to OWASP ZAP at {ZAP_URL}: {exc}") from exc

        tests = BASIC_TESTS if tier == "basic" else DEEP_TESTS
        scanner_type = "passive" if tier == "basic" else "active"
        require_scanners(zap, tests, scanner_type)

        # Isolate each run so old alerts cannot leak into a new report.
        zap.core.new_session(name=f"cybershield-{tier}-{int(time.time())}", overwrite=True)

        if tier == "basic":
            selected_ids = ",".join(sorted({pid for test in tests for pid in test["plugin_ids"]}, key=int))
            zap.pscan.disable_all_scanners()
            zap.pscan.enable_scanners(selected_ids)
            zap.spider.set_option_max_depth(2)
            spider_id = zap.spider.scan(target)
            if not str(spider_id).isdigit():
                raise HTTPException(status_code=502, detail=f"ZAP Spider could not start: {spider_id}")
            wait_for_scan(zap.spider.status, spider_id, SPIDER_TIMEOUT_SECONDS, "passive crawl")
            # Check the root response via ZAP as well; this covers Referrer-Policy
            # on ZAP versions without a native passive rule for that header.
            headers = read_headers_through_zap(target)
            wait_for_passive_scan(zap)
            alerts = zap.core.alerts(baseurl=target)
            missing_headers = []
            if headers is not None:
                missing_headers = [header for header in tests[0]["headers"] if header not in headers]
            check_results = build_test_results(tests, alerts, missing_headers)
            scanned_rule_ids = selected_ids.split(",")
            alert_names = [str(alert.get("name") or "").lower() for alert in alerts]
            synthetic_header_findings = []
            if missing_headers:
                for header in missing_headers:
                    if not any(header in name for name in alert_names):
                        synthetic_header_findings.append({
                            "id": f"basic-header-{header}",
                            "name": f"Missing security header: {header}",
                            "risk": "Low",
                            "confidence": "High",
                            "url": target,
                            "description": f"The {header} response header was not present on the root page fetched through ZAP.",
                            "solution": f"Configure the site to send an appropriate {header} response header.",
                            "evidence": f"Missing response header: {header}",
                            "plugin_id": "zap-proxied-header-check",
                        })
        else:
            selected_ids = ",".join(test["plugin_ids"][0] for test in tests)
            zap.ascan.disable_all_scanners()
            zap.ascan.enable_scanners(selected_ids)
            zap.spider.set_option_max_depth(2)
            spider_id = zap.spider.scan(target)
            if not str(spider_id).isdigit():
                raise HTTPException(status_code=502, detail=f"ZAP Spider could not start: {spider_id}")
            wait_for_scan(zap.spider.status, spider_id, SPIDER_TIMEOUT_SECONDS, "target discovery")
            ascan_id = zap.ascan.scan(target)
            if not str(ascan_id).isdigit():
                raise HTTPException(status_code=502, detail=f"ZAP Active Scan could not start: {ascan_id}")
            wait_for_scan(zap.ascan.status, ascan_id, ACTIVE_TIMEOUT_SECONDS, "active scan")
            alerts = zap.core.alerts(baseurl=target)
            check_results = build_test_results(tests, alerts)
            scanned_rule_ids = selected_ids.split(",")
            synthetic_header_findings = []

        # Only alerts belonging to this tier's selected rules are part of the
        # report; this keeps each mode to its five specified test groups.
        expected_ids = {pid for test in tests for pid in test["plugin_ids"]}
        findings = [
            {
                "id": alert.get("id", str(idx)),
                "name": alert.get("name", "Security finding"),
                "risk": alert.get("risk", "Informational"),
                "confidence": alert.get("confidence", "Unknown"),
                "url": alert.get("url", target),
                "description": alert.get("description", ""),
                "solution": alert.get("solution", ""),
                "evidence": str(alert.get("evidence", ""))[:300],
                "plugin_id": alert_plugin_id(alert),
            }
            for idx, alert in enumerate(alerts)
            if alert_plugin_id(alert) in expected_ids
        ]
        findings.extend(synthetic_header_findings)
        counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for finding in findings:
            risk = finding["risk"]
            counts[risk if risk in counts else "Informational"] += 1

        return {
            "status": "COMPLETED",
            "engine": "OWASP ZAP",
            "zap_version": version,
            "target": target,
            "tier": tier,
            "total_alerts": len(findings),
            "severity_counts": counts,
            "checks_run": sum(result["status"] != "NOT_RUN" for result in check_results),
            "checks_total": len(check_results),
            "check_results": check_results,
            "scanner_rule_ids": scanned_rule_ids,
            "findings": findings,
        }
    finally:
        SCAN_LOCK.release()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("index:app", host="0.0.0.0", port=8000, reload=True)
