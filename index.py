import time
import requests
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from zapv2 import ZAPv2

app = FastAPI(title="SecureScan ZAP Backend API")

# Allow Next.js frontend to communicate with this backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ZAP_URL = "http://localhost:8080"
ZAP_API_KEY = "securescan-local-key-123"


@app.get("/api/alerts")
def run_zap_automation(
    target: str = Query(default="http://testasp.vulnweb.com"),
    tier: str = Query(default="deep"),
):
    # 0. Normalize Target URL (ZAP requires http:// or https://)
    target = target.strip()
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    print(f"Connecting to ZAP API at {ZAP_URL}...")
    try:
        zap = ZAPv2(apikey=ZAP_API_KEY, proxies={"http": ZAP_URL, "https": ZAP_URL})
        print(f"Success! ZAP Version: {zap.core.version}")
    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail=f"Cannot connect to OWASP ZAP container on {ZAP_URL}. Make sure Docker is running (`docker start securescan-zap`). Error: {e}",
        )

    # --- CONFIGURE SPIDER LIMITS ---
    zap.spider.set_option_max_depth(2)
    print("Configured Spider maximum depth to 2 levels.")

    # 1. SPIDER (Discovery)
    print(f"\n[1/2] Starting Spider crawl for target: {target} (Mode: {tier.upper()})")
    scan_id = zap.spider.scan(target)

    if not str(scan_id).isdigit():
        raise HTTPException(
            status_code=400,
            detail=f"ZAP Spider failed to start for {target}. ZAP returned: {scan_id}",
        )

    while int(zap.spider.status(scan_id)) < 100:
        print(f"Spider progress: {zap.spider.status(scan_id)}%")
        time.sleep(2)

    print("Spider completed! Passive scanning logs generated.")

    # 2. ACTIVE SCAN (Only runs when tier is 'deep')
    if tier.lower() == "deep":
        # --- CONFIGURE ACTIVE SCANNER LIMITS ---
        zap.ascan.set_option_attack_policy("Default Policy")
        zap.ascan.set_option_target_params_injectable(31)

        print(f"\n[2/2] Starting Active Scan for target: {target}")
        print("WARNING: Sending active attack payloads...")
        ascan_id = zap.ascan.scan(target)

        if not str(ascan_id).isdigit():
            print(f"Warning: Active scan did not start (returned: {ascan_id}). Returning passive alerts.")
        else:
            # Production-ready resilient polling loop
            retries = 0
            max_retries = 10

            while True:
                try:
                    progress = int(zap.ascan.status(ascan_id))
                    print(f"Active Scan progress: {progress}%")
                    if progress >= 100:
                        break
                    retries = 0

                except (requests.exceptions.ProxyError, requests.exceptions.ConnectionError):
                    retries += 1
                    print(f"Warning: ZAP API connection dropped. Retrying ({retries}/{max_retries})...")
                    if retries >= max_retries:
                        raise HTTPException(status_code=500, detail="ZAP container crashed under load.")

                except Exception as e:
                    raise HTTPException(status_code=500, detail=f"Unexpected error during Active Scan: {e}")

                time.sleep(5)

            print("Active Scan completed!")
    else:
        print("\n[2/2] Basic/Passive mode selected. Skipping Active Scan.")

    # 3. RETRIEVE AND NORMALIZE RESULTS
    print("\nFetching alerts from database...")
    raw_alerts = zap.core.alerts(baseurl=target)

    normalized_findings = []
    severity_counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}

    for idx, alert in enumerate(raw_alerts):
        risk = alert.get("risk", "Informational")
        if risk in severity_counts:
            severity_counts[risk] += 1
        else:
            severity_counts["Informational"] += 1

        normalized_findings.append({
            "id": alert.get("id", str(idx)),
            "name": alert.get("name"),
            "risk": risk,
            "confidence": alert.get("confidence"),
            "url": alert.get("url"),
            "description": alert.get("description"),
            "solution": alert.get("solution"),
            "evidence": alert.get("evidence", "")[:300],  # Keep evidence short for UI
        })

    print(f"\n--- RETURNED {len(normalized_findings)} ALERTS TO UI ---")

    return {
        "status": "COMPLETED",
        "target": target,
        "tier": tier,
        "total_alerts": len(normalized_findings),
        "severity_counts": severity_counts,
        "findings": normalized_findings,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("index:app", host="0.0.0.0", port=8000, reload=True)