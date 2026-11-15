"use client";

import React, { useState, useEffect, useRef, useCallback } from "react";
import type { AuditReport } from "./api/audit/route";
import { explainFinding, FindingsPanel, PlainLanguageSummary } from "./ScanExtras";
import { formatFriendlyError, type FriendlyError } from "@/lib/errors";

const REMEDIATION_DB: Record<
  string,
  {
    name: string;
    desc: string;
    nginx: string;
    apache: string;
    cloudflare: string;
    nextjs: string;
    caddy: string;
  }
> = {
  "Strict-Transport-Security": {
    name: "Strict-Transport-Security (HSTS)",
    desc: "Enforces browsers to exclusively access the domain over HTTPS for 1 year, including subdomains.",
    nginx: 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
    apache: 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
    cloudflare:
      "// In Cloudflare Dashboard -> SSL/TLS -> Edge Certificates -> Enable HSTS\n// Max-Age: 12 months, Include Subdomains: ON, Preload: ON",
    nextjs:
      '// next.config.js\nmodule.exports = {\n  async headers() {\n    return [{\n      source: "/:path*",\n      headers: [{ key: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains; preload" }]\n    }];\n  }\n};',
    caddy: 'header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
  },
  "Content-Security-Policy": {
    name: "Content-Security-Policy (CSP)",
    desc: "Mitigates Cross-Site Scripting (XSS) and data injection by declaring approved content sources.",
    nginx:
      "add_header Content-Security-Policy \"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com;\" always;",
    apache:
      "Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self';\"",
    cloudflare:
      "// Add Transform Rule -> Modify Response Header\n// Header: Content-Security-Policy\n// Value: default-src 'self'; script-src 'self';",
    nextjs:
      '// next.config.js\nheaders: [{ key: "Content-Security-Policy", value: "default-src \'self\'; script-src \'self\';" }]',
    caddy: 'header Content-Security-Policy "default-src \'self\'; script-src \'self\';"',
  },
  "X-Frame-Options": {
    name: "X-Frame-Options",
    desc: "Defends against clickjacking by refusing iframe embedding across external origins.",
    nginx: 'add_header X-Frame-Options "SAMEORIGIN" always;',
    apache: 'Header always set X-Frame-Options "SAMEORIGIN"',
    cloudflare: "// Cloudflare Transform Rule -> Set X-Frame-Options to SAMEORIGIN",
    nextjs: 'headers: [{ key: "X-Frame-Options", value: "SAMEORIGIN" }]',
    caddy: 'header X-Frame-Options "SAMEORIGIN"',
  },
  "X-Content-Type-Options": {
    name: "X-Content-Type-Options",
    desc: "Prevents browser MIME-type sniffing vulnerabilities by enforcing declared MIME types.",
    nginx: 'add_header X-Content-Type-Options "nosniff" always;',
    apache: 'Header always set X-Content-Type-Options "nosniff"',
    cloudflare: "// Cloudflare Transform Rule -> Set X-Content-Type-Options to nosniff",
    nextjs: 'headers: [{ key: "X-Content-Type-Options", value: "nosniff" }]',
    caddy: 'header X-Content-Type-Options "nosniff"',
  },
  "Referrer-Policy": {
    name: "Referrer-Policy",
    desc: "Restricts referral info sent when following outbound hyperlinks, preventing sensitive URL leaks.",
    nginx: 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
    apache: 'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
    cloudflare:
      "// Cloudflare Transform Rule -> Set Referrer-Policy to strict-origin-when-cross-origin",
    nextjs:
      'headers: [{ key: "Referrer-Policy", value: "strict-origin-when-cross-origin" }]',
    caddy: 'header Referrer-Policy "strict-origin-when-cross-origin"',
  },
  "Permissions-Policy": {
    name: "Permissions-Policy",
    desc: "Restricts browser feature APIs such as camera, microphone, geolocation, and payment requests.",
    nginx:
      'add_header Permissions-Policy "geolocation=(), camera=(), microphone=()" always;',
    apache:
      'Header always set Permissions-Policy "geolocation=(), camera=(), microphone=()"',
    cloudflare:
      "// Cloudflare Transform Rule -> Set Permissions-Policy to geolocation=(), camera=(), microphone=()",
    nextjs:
      'headers: [{ key: "Permissions-Policy", value: "geolocation=(), camera=(), microphone=()" }]',
    caddy:
      'header Permissions-Policy "geolocation=(), camera=(), microphone=()"',
  },
};

interface TerminalLog {
  id: string;
  ts: string;
  tag: string;
  msg: string;
}

interface UserProfile {
  name: string;
  email: string;
  initials: string;
}

export default function CyberShieldPage() {
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const [targetInput, setTargetInput] = useState("");
  const [tier, setTier] = useState<"basic" | "deep">("basic");
  const [authorizedAttested, setAuthorizedAttested] = useState(false);
  const [isAuditing, setIsAuditing] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [errorDetails, setErrorDetails] = useState<{
    title: string;
    message: string;
    hint?: string;
    code?: string;
    isUserError?: boolean;
  } | null>(null);

  const showFriendlyError = (
    title: string,
    message: string,
    hint?: string,
    code?: string,
    isUserError = true
  ) => {
    setErrorMsg(message);
    setErrorDetails({ title, message, hint, code, isUserError });
  };

  const clearError = () => {
    setErrorMsg(null);
    setErrorDetails(null);
  };

  // Live Terminal
  const [isTerminalVisible, setIsTerminalVisible] = useState(false);
  const [terminalLogs, setTerminalLogs] = useState<TerminalLog[]>([]);
  const [termStatus, setTermStatus] = useState<"IDLE" | "ACTIVE" | "RUNNING" | "FINISHED" | "FAILED">("ACTIVE");

  // Results
  const [auditData, setAuditData] = useState<AuditReport | null>(null);
  const [animatedScore, setAnimatedScore] = useState(0);

  // Modals & Drawers
  const [isHistoryOpen, setIsHistoryOpen] = useState(false);
  const [scanHistory, setScanHistory] = useState<AuditReport[]>([]);
  const [remedModal, setRemedModal] = useState<{
    open: boolean;
    header: string;
    tab: "nginx" | "apache" | "cloudflare" | "nextjs" | "caddy";
  }>({ open: false, header: "Strict-Transport-Security", tab: "nginx" });
  const [remedCopied, setRemedCopied] = useState(false);

  const [authModal, setAuthModal] = useState<{
    open: boolean;
    tab: "signin" | "signup";
  }>({ open: false, tab: "signin" });
  const [authName, setAuthName] = useState("");
  const [authEmail, setAuthEmail] = useState("");
  const [authPassword, setAuthPassword] = useState("");
  const [userProfile, setUserProfile] = useState<UserProfile | null>(null);
  const [isProfileDropdownOpen, setIsProfileDropdownOpen] = useState(false);

  // Copy Buttons feedback
  const [copyJsonText, setCopyJsonText] = useState("Copy JSON Report");
  const [copyMdText, setCopyMdText] = useState("Copy Plain-Language Report");

  const inputRef = useRef<HTMLInputElement>(null);
  const terminalEndRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const cursorGlowRef = useRef<HTMLDivElement>(null);
  const cursorDotRef = useRef<HTMLDivElement>(null);
  // Initialize theme and history
  useEffect(() => {
    const savedTheme = (localStorage.getItem("cybershield-theme") as "dark" | "light") || "dark";
    setTheme(savedTheme);
    document.documentElement.setAttribute("data-theme", savedTheme);

    try {
      const savedHistory = JSON.parse(localStorage.getItem("cybershield-history") || "[]");
      setScanHistory(savedHistory);
    } catch {}
  }, []);

  const toggleTheme = () => {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem("cybershield-theme", next);
  };

  // Particle Canvas & Cursor
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animId: number;
    let mouseX = -300;
    let mouseY = -300;
    let smoothX = -300;
    let smoothY = -300;
    const sparks: Array<{
      x: number;
      y: number;
      vx: number;
      vy: number;
      radius: number;
      alpha: number;
      decay: number;
    }> = [];

    const handleResize = () => {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
    };
    handleResize();
    window.addEventListener("resize", handleResize);

    const handleMouseMove = (e: MouseEvent) => {
      mouseX = e.clientX;
      mouseY = e.clientY;
      if (cursorGlowRef.current) cursorGlowRef.current.style.opacity = "0.35";
      if (cursorDotRef.current) {
        cursorDotRef.current.style.left = `${mouseX}px`;
        cursorDotRef.current.style.top = `${mouseY}px`;
      }
      for (let i = 0; i < 2; i++) {
        sparks.push({
          x: mouseX,
          y: mouseY,
          vx: (Math.random() - 0.5) * 2,
          vy: (Math.random() - 0.5) * 2,
          radius: Math.random() * 2.8 + 1,
          alpha: 1,
          decay: Math.random() * 0.025 + 0.015,
        });
      }
    };

    const handleMouseLeave = () => {
      if (cursorGlowRef.current) cursorGlowRef.current.style.opacity = "0";
    };

    window.addEventListener("mousemove", handleMouseMove);
    window.addEventListener("mouseleave", handleMouseLeave);

    const render = () => {
      smoothX += (mouseX - smoothX) * 0.14;
      smoothY += (mouseY - smoothY) * 0.14;
      if (cursorGlowRef.current) {
        cursorGlowRef.current.style.left = `${smoothX}px`;
        cursorGlowRef.current.style.top = `${smoothY}px`;
      }

      ctx.clearRect(0, 0, canvas.width, canvas.height);
      const isDark = document.documentElement.getAttribute("data-theme") !== "light";
      const colorRgb = isDark ? "255, 106, 0" : "234, 88, 12";

      for (let i = sparks.length - 1; i >= 0; i--) {
        const s = sparks[i];
        s.x += s.vx;
        s.y += s.vy;
        s.alpha -= s.decay;
        s.radius *= 0.97;

        if (s.alpha <= 0 || s.radius <= 0.2) {
          sparks.splice(i, 1);
          continue;
        }

        ctx.beginPath();
        ctx.arc(s.x, s.y, s.radius, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(${colorRgb}, ${s.alpha * 0.7})`;
        ctx.fill();
      }

      animId = requestAnimationFrame(render);
    };
    render();

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener("resize", handleResize);
      window.removeEventListener("mousemove", handleMouseMove);
      window.removeEventListener("mouseleave", handleMouseLeave);
    };
  }, []);


  // Score counter animation
  useEffect(() => {
    if (!auditData) return;
    setAnimatedScore(0);
    const target = auditData.score;
    const inc = Math.max(1, Math.ceil(target / 25));
    let curr = 0;
    const interval = setInterval(() => {
      curr += inc;
      if (curr >= target) {
        curr = target;
        clearInterval(interval);
      }
      setAnimatedScore(curr);
    }, 30);
    return () => clearInterval(interval);
  }, [auditData]);

  // Terminal scroll to bottom
  useEffect(() => {
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [terminalLogs]);

  const addLog = (tag: string, msg: string) => {
    const ts = new Date().toISOString().substring(14, 23);
    setTerminalLogs((prev) => [
      ...prev,
      { id: `${Date.now()}-${Math.random()}`, ts, tag, msg },
    ]);
  };

  const saveReportToHistory = (report: AuditReport) => {
    setScanHistory((prev) => {
      const filtered = prev.filter((h) => h.target !== report.target);
      const next = [report, ...filtered].slice(0, 25);
      try {
        localStorage.setItem("cybershield-history", JSON.stringify(next));
      } catch {}
      return next;
    });
  };

  const handleTargetChange = (val: string) => {
    setTargetInput(val);
    setAuthorizedAttested(false);
  };

  const handleAudit = async (targetOverride?: string) => {
    const rawTarget = (targetOverride || targetInput).trim();
    if (!rawTarget) {
      showFriendlyError(
        "Target Domain Required",
        "Please enter a valid website hostname or URL (e.g. github.com, cloudflare.com) to start scanning.",
        "Tip: You can click any of the preset chips below for a one-click scan.",
        "BAD_INPUT",
        true
      );
      return;
    }

    if (tier === "deep" && !authorizedAttested) {
      showFriendlyError(
        "Authorization Attestation Required",
        "Please confirm that you have legal authorization to test this target domain under applicable cyber laws.",
        "Confirm the authorization attestation below before proceeding.",
        "ATTESTATION_REQUIRED",
        true
      );
      return;
    }
    clearError();
    setAuditData(null);
    setIsTerminalVisible(true);
    setTerminalLogs([]);
    setTermStatus("RUNNING");
    setIsAuditing(true);

    const now = new Date();
    const ts = now.toISOString().substring(14, 23);
    setTerminalLogs([
      { id: "1", ts, tag: "INIT", msg: `Auditing target: ${rawTarget} [Mode: ${tier.toUpperCase()}]` },
      { id: "2", ts, tag: tier === "deep" ? "ZAP_PROXY" : "DNS_LOOKUP", msg: tier === "deep" ? "Connecting to SecureScan ZAP Engine..." : "Resolving DNS record & socket connection..." },
    ]);

    const startTime = Date.now();
    addLog(tier === "deep" ? "ZAP_SCAN" : "AUDIT_START", `Initiating ${tier === "deep" ? "OWASP ZAP active scan" : "security audit"} for ${rawTarget}...`);

    try {
      let finalData: any = null;
      let isSuccess = false;

      // 1. Fetch Node Baseline Security Audit (handles real TLS socket + SPF/DMARC + Sensitive files)
      addLog("NODE_TELEMETRY", "Running Node.js TLS handshake, DNS email posture, and sensitive file audit...");
      const nodeRes = await fetch("/api/audit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url: rawTarget,
          tier,
          attested: authorizedAttested,
          user_id: userProfile?.email || undefined,
        }),
      });
      const nodeData = await nodeRes.json();
      
      if (!nodeRes.ok || nodeData.error) {
        const friendly = formatFriendlyError(nodeData.code || "AUDIT_ERROR", nodeData.error || nodeData.friendly_message);
        showFriendlyError(
          nodeData.title || friendly.title,
          nodeData.error || friendly.message,
          nodeData.hint || friendly.hint,
          nodeData.code || friendly.code,
          nodeData.is_user_error !== undefined ? nodeData.is_user_error : friendly.isUserError
        );
        addLog("NOTICE", `[${nodeData.code || "NOTICE"}] ${nodeData.error || friendly.message}`);
        setTermStatus("FAILED");
        setIsAuditing(false);
        return;
      }

      finalData = nodeData;
      isSuccess = true;

      // 2. Connect to SecureScan OWASP ZAP Backend (FastAPI on port 8000)
      try {
        addLog("ZAP_INIT", `Connecting to SecureScan ZAP engine on http://localhost:8000 [Tier: ${tier.toUpperCase()}]...`);
        const zapStartRes = await fetch(`http://localhost:8000/api/scan?target=${encodeURIComponent(rawTarget)}&tier=${tier}`, {
          method: "POST",
        });

        if (zapStartRes.ok) {
          const { scan_id } = await zapStartRes.json();
          addLog("ZAP_JOB", `Scan initiated (ID: ${scan_id?.slice(0, 8)}...). Polling engine status...`);

          // Resilient polling loop
          let zapCompleted = false;
          let zapResult: any = null;
          const pollMaxAttempts = tier === "deep" ? 60 : 30;
          const pollInterval = tier === "deep" ? 2500 : 1000;

          for (let attempt = 0; attempt < pollMaxAttempts; attempt++) {
            await new Promise((r) => setTimeout(r, pollInterval));
            const statusRes = await fetch(`http://localhost:8000/api/scan/${scan_id}/status`);
            if (!statusRes.ok) break;
            const statusData = await statusRes.json();
            
            addLog("ZAP_PROGRESS", `[${(statusData.phase || "scanning").toUpperCase()}] ${statusData.progress || 0}% completed`);

            if (statusData.status === "COMPLETED") {
              const resRes = await fetch(`http://localhost:8000/api/scan/${scan_id}/result`);
              if (resRes.ok) {
                zapResult = await resRes.json();
                zapCompleted = true;
              }
              break;
            } else if (statusData.status === "FAILED") {
              addLog("ZAP_WARN", `ZAP Engine reported error: ${statusData.error || "Scan failed"}`);
              break;
            }
          }

          if (zapCompleted && zapResult?.findings_from_zap) {
            addLog("ZAP_MERGE", `Merging ${zapResult.findings_from_zap.length} OWASP ZAP findings with Node telemetry...`);

            if (zapResult.warnings && Array.isArray(zapResult.warnings)) {
              zapResult.warnings.forEach((warn: string) => {
                addLog("ZAP_WARN", `[ADD-ON ALERT] ${warn}`);
              });
            }

            if (tier === "deep" && zapResult.rules_actually_enabled) {
              const enabledList = Object.keys(zapResult.rules_actually_enabled);
              addLog("ZAP_RULES", `Active scan plugins enabled: [${enabledList.join(", ")}]`);
              if (!enabledList.includes("41")) {
                addLog("ZAP_WARN", "[MISSING ADD-ON] Plugin 41 (Git Exposure) not found in ZAP. Install 'Beta Active Scan Rules'.");
              }
              if (!enabledList.includes("40040")) {
                addLog("ZAP_WARN", "[MISSING ADD-ON] Plugin 40040 (CORS Misconfig) not found in ZAP. Install 'Alpha Active Scan Rules'.");
              }
            }

            if (tier === "basic" && zapResult.retirejs_available === false) {
              addLog("ZAP_WARN", "[MISSING ADD-ON] Retire.js scanner not found in ZAP. Install 'retire' add-on to detect vulnerable JS libraries.");
            }

            const zapFindings = zapResult.findings_from_zap.map((f: any, idx: number) => ({
              id: f.id || `ZAP-${idx + 1}`,
              title: f.name || "ZAP Detected Vulnerability",
              severity: f.risk || "Medium",
              confidence: f.confidence === "High" ? "confirmed" : "likely",
              evidence: f.evidence || f.url || "",
              cwe: f.cwe || "CWE-693",
              owasp: f.category || "A05:2021-Security Misconfiguration",
              wstg: "WSTG-CONF-07",
              remediation: f.solution || f.description || "Review configuration in accordance with OWASP guidance.",
              tier,
            }));

            // Merge findings
            finalData.findings = [...(finalData.findings || []), ...zapFindings];

            // In Basic tier: merge security headers, cookie flags, server info, and directory browsing
            if (tier === "basic") {
              zapResult.findings_from_zap.forEach((zf: any) => {
                if (zf.category === "security_headers" && !finalData.http.missing_headers.some((h: any) => h.name.toLowerCase() === zf.name.toLowerCase())) {
                  finalData.http.missing_headers.push({
                    name: zf.name,
                    severity: zf.risk || "Medium",
                    description: zf.description || zf.solution || "",
                  });
                } else if (zf.category === "server_info_disclosure") {
                  finalData.http.leakage.push({
                    header: zf.name,
                    value: zf.evidence || "Server banner exposed",
                    risk: zf.risk || "Low",
                  });
                }
              });
            }

            // Recalculate score reflecting both Node + ZAP findings
            const highCount = finalData.findings.filter((f: any) => ["Critical", "High"].includes(f.severity)).length;
            const medCount = finalData.findings.filter((f: any) => f.severity === "Medium").length;
            const lowCount = finalData.findings.filter((f: any) => f.severity === "Low").length;
            finalData.score = Math.max(0, 100 - (highCount * 20) - (medCount * 10) - (lowCount * 5));
            if (finalData.score >= 90) { finalData.grade = "A"; finalData.grade_color = "#10b981"; finalData.verdict = "Secure & Resilient"; }
            else if (finalData.score >= 70) { finalData.grade = "B"; finalData.grade_color = "#fbbf24"; finalData.verdict = "Adequate Security"; }
            else if (finalData.score >= 50) { finalData.grade = "C"; finalData.grade_color = "#f59e0b"; finalData.verdict = "Action Required"; }
            else if (finalData.score >= 30) { finalData.grade = "D"; finalData.grade_color = "#ea580c"; finalData.verdict = "Vulnerable Target"; }
            else { finalData.grade = "F"; finalData.grade_color = "#ef4444"; finalData.verdict = "Critically Exposed"; }
          }
        } else {
          const errBody = await zapStartRes.json().catch(() => ({}));
          addLog("ZAP_NOTICE", `ZAP Engine: ${errBody.detail || "Service inactive"}. Displaying Node telemetry.`);
        }
      } catch (zapErr: any) {
        addLog("ZAP_OFFLINE", "SecureScan ZAP backend (port 8000) not reachable. Full Node telemetry loaded.");
      }

      const high = rawData.severity_counts?.High || 0;
      const medium = rawData.severity_counts?.Medium || 0;
      const low = rawData.severity_counts?.Low || 0;
      const calculatedScore = Math.max(0, 100 - high * 20 - medium * 10 - low * 5);
      let grade = "A", grade_color = "#10b981";
      if (calculatedScore < 90) { grade = "B"; grade_color = "#fbbf24"; }
      if (calculatedScore < 70) { grade = "C"; grade_color = "#f59e0b"; }
      if (calculatedScore < 50) { grade = "D"; grade_color = "#ea580c"; }
      if (calculatedScore < 30) { grade = "F"; grade_color = "#ef4444"; }
      const findings = rawData.findings || [];
      const deductions = findings.map((finding: any) => finding.name || "Security finding");

      finalData = {
        target: rawData.target,
        full_url: rawData.target,
        timestamp: new Date().toISOString(),
        score: calculatedScore,
        grade,
        grade_color,
        verdict: deductions.length ? `${deductions.length} ZAP alert(s) need review` : "No alerts from the selected ZAP checks",
        tier,
        engine: rawData.engine,
        zap_version: rawData.zap_version,
        checks_run: rawData.checks_run,
        checks_total: rawData.checks_total,
        check_results: rawData.check_results,
        scanner_rule_ids: rawData.scanner_rule_ids,
        network: { ip: "Not measured by ZAP", latency_ms: 0 },
        http: {
          infrastructure: "OWASP ZAP",
          status_code: 0,
          redirect_secure: false,
          missing_headers: [],
          present_headers: {},
          leakage: [],
          cookies: [],
        },
        tls: {
          tls_version: "Not measured by these ZAP checks",
          cipher_suite: "Not measured",
          issuer_org: "Not measured",
          cert_expires_in_days: 0,
          expires_at: "Not measured",
          sans_count: 0,
          sans_sample: [],
          cert_valid: false,
          protocol_secure: false,
          fingerprint_sha256: "Not measured",
        },
        findings,
        deductions,
        limitations: ["A passing ZAP check means no matching alert was found; it is not proof that the site is secure."],
      };
      isSuccess = true;

      if (isSuccess && finalData) {
        addLog("SUCCESS", `Audit completed in ${Date.now() - startTime}ms. Threat Score: ${finalData.score}/100 [Grade ${finalData.grade}]`);
        setTermStatus("FINISHED");

        setTimeout(() => {
          setAuditData(finalData);
          saveReportToHistory(finalData);
          setIsAuditing(false);
        }, 500);
      }

    } catch (err: any) {
      setTermStatus("FAILED");
      addLog("ERROR", err.message || "Audit connection failed");
      const friendly = formatFriendlyError("UNEXPECTED_ERROR", err.message);
      showFriendlyError(
        friendly.title,
        err.message || friendly.message,
        friendly.hint,
        friendly.code,
        friendly.isUserError
      );
      setIsAuditing(false);
    }
  };

  const handleQuickPreset = (domain: string) => {
    handleTargetChange(domain);
    clearError();
  };

  const copyJson = () => {
    if (!auditData) return;
    navigator.clipboard.writeText(JSON.stringify(auditData, null, 2));
    setCopyJsonText("Copied!");
    setTimeout(() => setCopyJsonText("Copy JSON Report"), 2000);
  };

  const downloadJson = () => {
    if (!auditData) return;
    const blob = new Blob([JSON.stringify(auditData, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `cybershield-${auditData.target}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const copyMarkdown = () => {
    if (!auditData) return;
    const d = auditData;
    const findings = (d.findings || []) as any[];
    const checks = d.check_results || [];
    const highPriority = findings.filter((f) => ["Critical", "High"].includes(f.severity || f.risk)).length;
    const findingLines = findings.length
      ? findings.map((f) => {
          const title = f.title || f.name || "Security observation";
          const evidence = f.evidence || f.description || "No additional details were provided by the scanner.";
          const recommendation = f.remediation || f.solution || "Review this item with your development or security team.";
          return `### ${f.severity || f.risk || "Informational"}: ${title}\n\n**In plain language:** ${explainFinding(title, f.description || evidence)}\n\n**What the scan saw:** ${evidence}\n\n**Suggested next step:** ${recommendation}`;
        }).join("\n\n")
      : "The automated checks did not flag any issues. This does not prove the site is completely secure.";
    const scanDescription = d.tier === "deep"
      ? "The scan sent active test requests. Only run this scan against systems you are authorized to test."
      : "The scan reviewed publicly visible settings and responses without attempting to exploit the site.";
    const checkLines = checks.length
      ? checks.map((check) => `- **${check.status === "PASS" ? "No alert" : check.status === "FAIL" ? "Finding" : "Not run"} — ${check.name}:** ${check.description}${check.evidence?.length ? ` Evidence: ${check.evidence.join("; ")}` : ""}`).join("\n")
      : "No grouped check results were returned by the scanner.";
    const md = `# Security report for ${d.target}

- **Date:** ${new Date(d.timestamp).toLocaleString()}
- **Scan type:** ${d.tier === "deep" ? "Deep scan (active checks)" : "Basic scan (passive checks)"}
- **Overall result:** ${highPriority ? `${highPriority} high-priority ${highPriority === 1 ? "item needs" : "items need"} attention` : findings.length ? `${findings.length} item(s) to review` : "No issues flagged by the automated checks"}
- **Score:** ${d.score}/100 (${d.grade})

## What this means

${scanDescription} The score is a summary indicator, not a guarantee that the site is safe. Automated checks can miss issues and some findings need human review.

## The five checks in this scan

${checkLines}

## Findings and recommended actions

${findingLines}

## What to do next

1. Address Critical and High findings first.
2. Ask a developer to verify each finding and apply its suggested fix.
3. Review any checks marked as needing a person.
4. Run another scan after making changes.

*Generated by CyberShield*`;

    navigator.clipboard.writeText(md);
    setCopyMdText("Copied Markdown!");
    setTimeout(() => setCopyMdText("Copy Plain-Language Report"), 2000);
  };

  const openRemediation = (headerName: string) => {
    setRemedModal({
      open: true,
      header: headerName,
      tab: "nginx",
    });
    setRemedCopied(false);
  };

  const copyRemedSnippet = () => {
    const item = REMEDIATION_DB[remedModal.header];
    const snippet = item ? item[remedModal.tab] : `// Configuration for ${remedModal.header}`;
    navigator.clipboard.writeText(snippet);
    setRemedCopied(true);
    setTimeout(() => setRemedCopied(false), 2000);
  };

  const handleAuthSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const name = authName.trim() || authEmail.split("@")[0] || "SecOps Analyst";
    const initials = name.slice(0, 2).toUpperCase();
    setUserProfile({ name, email: authEmail, initials });
    setAuthModal((p) => ({ ...p, open: false }));
  };

  const handleSignOut = () => {
    setUserProfile(null);
    setIsProfileDropdownOpen(false);
  };

  const clearHistory = () => {
    if (confirm("Clear all local audit history?")) {
      setScanHistory([]);
      localStorage.removeItem("cybershield-history");
    }
  };

  // Gauge calculations
  const circumference = 2 * Math.PI * 60;
  const gaugeOffset = auditData
    ? circumference - (auditData.score / 100) * circumference
    : circumference;

  return (
    <>
      {/* ═══════════ AMBIENT CANVAS & CURSOR ═══════════ */}
      <div className="ambient-canvas" aria-hidden="true">
        <div className="gradient-flow" />
        <div className="cyber-grid" />
        <div className="pulse-orb pulse-orb-1" />
        <div className="pulse-orb pulse-orb-2" />
        <div className="pulse-orb pulse-orb-3" />
      </div>
      <div className="cursor-glow" id="cursorGlow" ref={cursorGlowRef} />
      <div className="cursor-dot" id="cursorDot" ref={cursorDotRef} />
      <canvas
        id="particleCanvas"
        ref={canvasRef}
        style={{
          position: "fixed",
          top: 0,
          left: 0,
          width: "100%",
          height: "100%",
          pointerEvents: "none",
          zIndex: 9998,
        }}
      />

      {/* ═══════════ NAVIGATION BAR ═══════════ */}
      <nav className="nav-bar">
        <div className="nav-inner">
          <a
            href="#"
            className="nav-brand"
            onClick={(e) => {
              e.preventDefault();
              window.scrollTo({ top: 0, behavior: "smooth" });
            }}
          >
            {/* Creative Compact Cyber Shield Logo Mark */}
            <div className="brand-logo-mark">
              <div className="logo-mark-glow" />
              <div className="logo-mark-frame">
                <svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
                  <path
                    d="M16 3L6 7V15C6 21.5 10.3 27.5 16 29C21.7 27.5 26 21.5 26 15V7L16 3Z"
                    stroke="url(#navShieldGrad)"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                  <path
                    d="M16 8L10 11V15C10 19.5 12.6 23.6 16 24.8C19.4 23.6 22 19.5 22 15V11L16 8Z"
                    fill="url(#navShieldInnerGrad)"
                    opacity="0.45"
                  />
                  <circle cx="16" cy="16" r="3" fill="#ff731d" />
                  <line x1="16" y1="11" x2="16" y2="13" stroke="#ff731d" strokeWidth="1.8" strokeLinecap="round" />
                  <line x1="16" y1="19" x2="16" y2="21" stroke="#ff731d" strokeWidth="1.8" strokeLinecap="round" />
                  <line x1="11" y1="16" x2="13" y2="16" stroke="#ff731d" strokeWidth="1.8" strokeLinecap="round" />
                  <line x1="19" y1="16" x2="21" y2="16" stroke="#ff731d" strokeWidth="1.8" strokeLinecap="round" />
                  <defs>
                    <linearGradient id="navShieldGrad" x1="6" y1="3" x2="26" y2="29" gradientUnits="userSpaceOnUse">
                      <stop stopColor="#ff3b30" />
                      <stop offset="0.5" stopColor="#ff731d" />
                      <stop offset="1" stopColor="#ffb300" />
                    </linearGradient>
                    <linearGradient id="navShieldInnerGrad" x1="10" y1="8" x2="22" y2="24.8" gradientUnits="userSpaceOnUse">
                      <stop stopColor="#ff731d" />
                      <stop offset="1" stopColor="#ff3b30" stopOpacity="0" />
                    </linearGradient>
                  </defs>
                </svg>
              </div>
            </div>
            <div className="brand-text-wrapper">
              <span className="nav-brand-text">CYBERSHIELD</span>
              <span className="nav-brand-sub">Threat Intelligence</span>
            </div>
          </a>

          <div className="nav-actions">
            {/* History Drawer Trigger */}
            <div className="chromatic-capsule" style={{ position: "relative" }}>
              <button
                className="chromatic-circle-btn"
                id="historyDrawerBtn"
                onClick={() => {
                  setIsHistoryOpen(true);
                }}
                title="View Audit History [H]"
                aria-label="Scan history"
              >
                <div className="chromatic-circle-inner">
                  <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                    <circle cx="12" cy="12" r="10" />
                    <polyline points="12 6 12 12 16 14" />
                  </svg>
                </div>
              </button>
              <span className="history-count-badge" id="historyCounter">{scanHistory.length}</span>
            </div>

            {/* Theme Switcher */}
            <div className="chromatic-capsule">
              <button
                className="chromatic-circle-btn"
                id="themeToggleBtn"
                onClick={toggleTheme}
                title="Toggle Theme"
                aria-label="Toggle theme"
              >
                <div className="chromatic-circle-inner">
                  {theme === "light" ? (
                    <svg className="theme-icon-sun" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                      <circle cx="12" cy="12" r="5" />
                      <line x1="12" y1="1" x2="12" y2="3" />
                      <line x1="12" y1="21" x2="12" y2="23" />
                      <line x1="4.22" y1="4.22" x2="5.64" y2="5.64" />
                      <line x1="18.36" y1="18.36" x2="19.78" y2="19.78" />
                      <line x1="1" y1="12" x2="3" y2="12" />
                      <line x1="21" y1="12" x2="23" y2="12" />
                      <line x1="4.22" y1="19.78" x2="5.64" y2="18.36" />
                      <line x1="18.36" y1="5.64" x2="19.78" y2="4.22" />
                    </svg>
                  ) : (
                    <svg className="theme-icon-moon" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
                    </svg>
                  )}
                </div>
              </button>
            </div>

            {/* Pill Button for Login */}
            {!userProfile ? (
              <button
                className="auth-pill-btn"
                id="openAuthBtn"
                onClick={() => {
                  setAuthModal({ open: true, tab: "signin" });
                }}
              >
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                  <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                </svg>
                <span>SecOps Login</span>
              </button>
            ) : (
              <div className="profile-hub" id="profileHub" style={{ position: "relative" }}>
                <div className="chromatic-capsule">
                  <button
                    className="chromatic-circle-btn"
                    id="profileMenuBtn"
                    onClick={(e) => {
                      e.stopPropagation();
                      setIsProfileDropdownOpen((prev) => !prev);
                    }}
                  >
                    <div
                      className="chromatic-circle-inner"
                      id="userInitials"
                      style={{
                        fontWeight: 800,
                        fontFamily: "var(--font-mono)",
                        fontSize: "0.85rem",
                      }}
                    >
                      {userProfile.initials}
                    </div>
                  </button>
                  <span className="online-dot" />
                </div>

                {isProfileDropdownOpen && (
                  <div
                    className="profile-dropdown ember-card open"
                    id="profileDropdown"
                    onClick={(e) => e.stopPropagation()}
                  >
                    <div className="profile-dropdown-header">
                      <div className="profile-dropdown-avatar" id="dropdownAvatar">{userProfile.initials}</div>
                      <div className="profile-dropdown-info">
                        <h4 id="dropdownUserName">{userProfile.name}</h4>
                        <span className="role-badge">Lead Analyst</span>
                      </div>
                    </div>
                    <button
                      className="profile-dropdown-item"
                      onClick={() => {
                        setIsHistoryOpen(true);
                        setIsProfileDropdownOpen(false);
                      }}
                    >
                      <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                        <circle cx="12" cy="12" r="10" />
                        <polyline points="12 6 12 12 16 14" />
                      </svg>
                      Audit History
                    </button>
                    <button
                      className="profile-dropdown-item"
                      onClick={() =>
                        alert(
                          `API Integration Key: CS-SEC-${Math.random()
                            .toString(36)
                            .substring(2, 10)
                            .toUpperCase()}`
                        )
                      }
                    >
                      <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                        <path d="M15 7a2 2 0 0 1 2 2m4 0a6 6 0 0 1-7.743 5.743L11 17H9v2H7v2H4a1 1 0 0 1-1-1v-2.586a1 1 0 0 1 .293-.707l5.964-5.964A6 6 0 1 1 21 9z" />
                      </svg>
                      API Credentials
                    </button>
                    <div className="profile-dropdown-divider" />
                    <button className="profile-dropdown-item danger" id="signOutBtn" onClick={handleSignOut}>
                      <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                        <path d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 0 1-3 3H6a3 3 0 0 1-3-3V7a3 3 0 0 1 3-3h4a3 3 0 0 1 3 3v1" />
                      </svg>
                      Sign Out
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </nav>

      {/* ═══════════ MAIN CONTENT ═══════════ */}
      <main className="main-content">
        {/* Hero Section */}
        <section className="hero">
          <div>
            <div className="hero-pill-badge">
              <span className="live-dot" />
              <span className="badge-text-desktop">Real-Time Threat Intelligence • TLS 1.3 • Cryptographic Assurance</span>
              <span className="badge-text-mobile">Real-Time Threat Intel • TLS 1.3</span>
            </div>
          </div>

          <h1 className="hero-title">CYBERSHIELD</h1>
          <p className="hero-desc">
            Automated <strong>TLS Cryptography Audit</strong> •{" "}
            <strong>HTTP Security Headers</strong> • <strong>Cookie Hygiene</strong> — Comprehensive threat defense for cloud infrastructure.
          </p>
          <div className="hero-kbd-hint">
            <kbd>Enter</kbd> to launch audit · <kbd>Ctrl</kbd>+<kbd>K</kbd> to focus target · <kbd>H</kbd> for history
          </div>
        </section>

        {/* Search Cockpit */}
        <section className="ember-card search-cockpit">
          {/* ── Scan Tier Selector ── */}
          <div className="tier-selector-row">
            <button
              type="button"
              className={`tier-btn ${tier === "basic" ? "active" : ""}`}
              onClick={() => {
                setTier("basic");
                setAuthorizedAttested(false);
              }}
            >
              <svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
              Basic Scan
              <span className="tier-badge">Passive</span>
            </button>
            <button
              type="button"
              className={`tier-btn ${tier === "deep" ? "active" : ""}`}
              onClick={() => {
                setTier("deep");
              }}
            >
              <svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="10" />
                <path d="M12 8v4m0 4h.01" />
              </svg>
              Deep Scan
              <span className="tier-badge deep">Active</span>
            </button>
          </div>

          {tier === "deep" && (
            <label className="verify-attest">
              <input
                type="checkbox"
                checked={authorizedAttested}
                onChange={(e) => setAuthorizedAttested(e.target.checked)}
              />
              <span>
                <strong>Legal Attestation & Scope Agreement:</strong> I have explicit authorization to perform active security tests on this domain and agree to test only within that authorized scope.
              </span>
            </label>
          )}

          <div className="search-input-group">
            <div className="search-wrapper">
              <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="11" cy="11" r="8" />
                <line x1="21" y1="21" x2="16.65" y2="16.65" />
              </svg>
              <input
                ref={inputRef}
                type="text"
                id="targetInput"
                className="target-input"
                placeholder="Enter domain or URL (e.g. github.com)"
                value={targetInput}
                onChange={(e) => handleTargetChange(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    handleAudit();
                  }
                }}
                autoComplete="off"
                spellCheck="false"
              />
            </div>

            <button
              id="scanBtn"
              className="audit-btn"
              disabled={isAuditing}
              onClick={() => handleAudit()}
            >
              <div className="audit-btn-inner">
                <span>
                  {isAuditing
                    ? tier === "deep" ? "Deep Scanning..." : "Auditing..."
                    : tier === "deep" ? "Deep Scan" : "Audit Target"}
                </span>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M4.5 16.5c-1.5 1.26-2 5-2 5s3.74-.5 5-2c.71-.84.7-2.13-.09-2.91a2.18 2.18 0 0 0-2.91-.09z" />
                  <path d="M12 15l-3-3a22 22 0 0 1 2-3.95A12.88 12.88 0 0 1 22 2c0 2.72-.78 7.5-6 11a22.35 22.35 0 0 1-4 2z" />
                  <path d="M9 12H4s.55-3.03 2-4c1.62-1.08 5 0 5 0" />
                  <path d="M12 15v5s3.03-.55 4-2c1.08-1.62 0-5 0-5" />
                </svg>
              </div>
            </button>
          </div>

          <div className="quick-targets-row">
            <span className="quick-targets-label">Preset Targets:</span>
            <button type="button" className="quick-chip" onClick={() => handleQuickPreset("http://testasp.vulnweb.com")}>
              testasp.vulnweb.com
            </button>
            <button type="button" className="quick-chip" onClick={() => handleQuickPreset("github.com")}>
              github.com
            </button>
            <button type="button" className="quick-chip" onClick={() => handleQuickPreset("cloudflare.com")}>
              cloudflare.com
            </button>
          </div>
        </section>

        {/* Friendly Error Alert Card */}
        {(errorDetails || errorMsg) && (
          <div id="errorAlert" className="error-alert" style={{ display: "block" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: "1rem" }}>
              <div style={{ flex: 1 }}>
                <h4>
                  <svg width="22" height="22" fill="none" stroke="currentColor" strokeWidth="2.2" viewBox="0 0 24 24" strokeLinecap="round" strokeLinejoin="round">
                    <circle cx="12" cy="12" r="10" />
                    <line x1="12" y1="8" x2="12" y2="12" />
                    <line x1="12" y1="16" x2="12.01" y2="16" />
                  </svg>
                  {errorDetails?.title || "Security Notice"}
                  {errorDetails && (
                    <span
                      style={{
                        fontSize: "0.72rem",
                        padding: "2px 8px",
                        borderRadius: "12px",
                        background: errorDetails.isUserError ? "rgba(255, 183, 3, 0.18)" : "rgba(255, 34, 63, 0.18)",
                        color: errorDetails.isUserError ? "#ffb703" : "#ff4d4d",
                        border: `1px solid ${errorDetails.isUserError ? "rgba(255, 183, 3, 0.35)" : "rgba(255, 34, 63, 0.35)"}`,
                        fontWeight: 600,
                        letterSpacing: "0.04em",
                        textTransform: "uppercase",
                      }}
                    >
                      {errorDetails.isUserError ? "Policy / Input Guidance" : "System / Network Notice"}
                    </span>
                  )}
                </h4>
                <p id="errorMessage" style={{ margin: "6px 0 10px 0", lineHeight: 1.55 }}>
                  {errorDetails?.message || errorMsg}
                </p>
                {errorDetails?.hint && (
                  <div
                    style={{
                      display: "flex",
                      alignItems: "flex-start",
                      gap: "8px",
                      background: "rgba(0, 0, 0, 0.25)",
                      padding: "8px 12px",
                      borderRadius: "10px",
                      border: "1px solid rgba(255, 255, 255, 0.08)",
                      fontSize: "0.84rem",
                      color: "var(--text-secondary)",
                      marginTop: "6px",
                    }}
                  >
                    <span style={{ fontSize: "1rem" }}>💡</span>
                    <span>
                      <strong style={{ color: "var(--text-primary)" }}>Helpful Suggestion: </strong>
                      {errorDetails.hint}
                    </span>
                  </div>
                )}
              </div>
              <button
                type="button"
                onClick={clearError}
                style={{
                  background: "transparent",
                  border: "none",
                  color: "var(--text-muted)",
                  cursor: "pointer",
                  fontSize: "1.2rem",
                  padding: "4px 8px",
                  lineHeight: 1,
                  borderRadius: "6px",
                }}
                title="Dismiss message"
              >
                ✕
              </button>
            </div>

            {/* Quick Helper Actions */}
            <div style={{ marginTop: "12px", display: "flex", gap: "10px", flexWrap: "wrap" }}>
              {(errorDetails?.code === "DENYLISTED" || errorDetails?.code === "IP_LITERAL" || errorDetails?.code === "INTERNAL_HOST") && (
                <button
                  type="button"
                  className="action-btn"
                  style={{ fontSize: "0.78rem", padding: "5px 12px" }}
                  onClick={() => {
                    handleQuickPreset("cloudflare.com");
                  }}
                >
                  Try Demo Target: cloudflare.com
                </button>
              )}
              <button
                type="button"
                className="action-btn"
                style={{ fontSize: "0.78rem", padding: "5px 12px", opacity: 0.8 }}
                onClick={clearError}
              >
                Dismiss Notice
              </button>
            </div>
          </div>
        )}

        {/* Live Hacker Terminal */}
        {isTerminalVisible && (
          <div id="liveTerminal" className="terminal-container" style={{ display: "block" }}>
            <div className="terminal-topbar">
              <div className="terminal-dots">
                <span className="terminal-dot dot-red" />
                <span className="terminal-dot dot-yellow" />
                <span className="terminal-dot dot-green" />
              </div>
              <div className="terminal-title">
                <svg width="15" height="15" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                  <polyline points="4 17 10 11 4 5" />
                  <line x1="12" y1="19" x2="20" y2="19" />
                </svg>
                CYBERSHIELD_AGENT // THREAT_TELEMETRY_ENGINE  
                <span style={{ fontSize: "0.65rem", color: "var(--text-muted)", opacity: 0.7, fontStyle: "italic" }}>[LIVE ZAP STREAM]</span>
              </div>
              <div
                id="termStatus"
                style={{
                  fontFamily: "var(--font-mono)",
                  fontSize: "0.72rem",
                  color:
                    termStatus === "RUNNING"
                      ? "var(--flame-orange)"
                      : termStatus === "FAILED"
                      ? "var(--danger)"
                      : "var(--success)",
                }}
              >
                {termStatus}
              </div>
            </div>
            <div className="terminal-body" id="terminalLogs">
              {terminalLogs.map((log) => (
                <div key={log.id} className="terminal-line">
                  <span className="term-ts">[{log.ts}]</span>
                  <span className="term-tag">{log.tag}</span>
                  <span className="term-msg">{log.msg}</span>
                </div>
              ))}
              <div ref={terminalEndRef} />
            </div>
          </div>
        )}

        {/* Audit Results Container */}
        {auditData && (
          <section id="resultsSection" className="results-wrapper" style={{ display: "flex" }}>
            {/* Executive Score Banner */}
            <div className="ember-card score-banner">
              <div className="target-header-col">
                <h2 id="resTarget">{auditData.target}</h2>
                <p id="resVerdict" style={{ color: "var(--text-secondary)", fontSize: "0.95rem" }}>
                  {auditData.verdict} —{" "}
                  {auditData.engine === "OWASP ZAP"
                    ? `${auditData.checks_run || 0} of ${auditData.checks_total || 5} check groups returned results`
                    : auditData.deductions.length > 0
                      ? `${auditData.deductions.length} vulnerabilities detected`
                      : "Zero critical flaws"}
                </p>
                <div className="target-meta-row">
                  {auditData.engine !== "OWASP ZAP" && <span className="meta-pill" id="metaIp">
                    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <circle cx="12" cy="12" r="10" />
                      <line x1="2" y1="12" x2="22" y2="12" />
                      <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
                    </svg>
                    <span id="resIp">{auditData.network.ip}</span>
                  </span>}
                  {auditData.engine !== "OWASP ZAP" && <span className="meta-pill" id="metaLatency">
                    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
                    </svg>
                    <span id="resLatency">{auditData.network.latency_ms}ms ping</span>
                  </span>}
                  <span className="meta-pill" id="metaInfra">
                    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z" />
                    </svg>
                    <span id="resInfra">{auditData.http.infrastructure}</span>
                  </span>
                  <span className="meta-pill" id="metaTimestamp">Audited {auditData.timestamp}</span>
                </div>
              </div>

              <div className="score-display-group">
                <div className="gauge-wrapper">
                  <svg className="gauge-svg" viewBox="0 0 130 130">
                    <circle className="gauge-bg" cx="65" cy="65" r="60" />
                    <circle
                      className="gauge-fg"
                      id="gaugeFg"
                      cx="65"
                      cy="65"
                      r="60"
                      style={{
                        strokeDashoffset: gaugeOffset,
                        stroke: auditData.grade_color,
                      }}
                    />
                  </svg>
                  <div className="gauge-inner-text">
                    <div
                      className="gauge-number"
                      id="resScoreNum"
                      style={{ color: auditData.grade_color }}
                    >
                      {animatedScore}
                    </div>
                    <div className="gauge-label">Security Score</div>
                  </div>
                </div>

                <div
                  className="grade-gemstone"
                  id="gradeGemstone"
                  style={{ background: auditData.grade_color }}
                >
                  <span className="grade-char" id="resGradeChar">{auditData.grade}</span>
                  <span className="grade-subtext">GRADE</span>
                </div>
              </div>
            </div>

            <PlainLanguageSummary
              findings={auditData.findings}
              checks={auditData.check_results}
              tier={auditData.tier}
              target={auditData.target}
              score={auditData.score}
            />

            {auditData.engine !== "OWASP ZAP" && (
              <>
            {/* Fast Metrics Bar */}
            <div className="fast-metrics-bar">
              <div className="ember-card metric-tile">
                <div className="metric-label">TLS Protocol</div>
                <div className="metric-value" id="fastTlsVer">{auditData.tls.tls_version || "N/A"}</div>
              </div>
              <div className="ember-card metric-tile">
                <div className="metric-label">Cert Validity</div>
                <div className="metric-value" id="fastCertDays">{auditData.tls.cert_expires_in_days} Days</div>
              </div>
              <div className="ember-card metric-tile">
                <div className="metric-label">HTTPS Redirect</div>
                <div className="metric-value" id="fastRedirect">
                  {auditData.http.redirect_secure ? "Enforced" : "None"}
                </div>
              </div>
              <div className="ember-card metric-tile">
                <div className="metric-label">HTTP Status</div>
                <div className="metric-value" id="fastHttpStatus">{auditData.http.status_code || 200} OK</div>
              </div>
            </div>

            {/* TLS / Cryptographic Status Card */}
            <div className="ember-card audit-card">
              <div className="audit-card-header">
                <div className="audit-card-title">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                    <circle cx="12" cy="16" r="1" />
                  </svg>
                  Cryptographic Architecture & TLS Chain
                </div>
                <div
                  id="tlsBadge"
                  className={`status-badge ${
                    auditData.tls.cert_valid && auditData.tls.protocol_secure
                      ? "badge-secure"
                      : auditData.tls.cert_valid
                      ? "badge-warning"
                      : "badge-danger"
                  }`}
                >
                  {auditData.tls.cert_valid && auditData.tls.protocol_secure
                    ? "STRONG CRYPTOGRAPHY"
                    : auditData.tls.cert_valid
                    ? "LEGACY PROTOCOL"
                    : "INSECURE / EXPIRED"}
                </div>
              </div>

              <div className="info-grid">
                <div className="info-tile">
                  <div className="info-tile-label">Negotiated Protocol</div>
                  <div
                    className="info-tile-value"
                    id="tlsVersionVal"
                    style={{ fontFamily: "var(--font-mono)", color: "var(--flame-orange)" }}
                  >
                    {auditData.tls.tls_version || "N/A"}
                  </div>
                </div>
                <div className="info-tile">
                  <div className="info-tile-label">Active Cipher Suite</div>
                  <div
                    className="info-tile-value"
                    id="tlsCipherVal"
                    style={{ fontFamily: "var(--font-mono)", fontSize: "0.84rem" }}
                  >
                    {auditData.tls.cipher_suite || "Unknown"}
                  </div>
                </div>
                <div className="info-tile">
                  <div className="info-tile-label">Certificate Authority (Issuer)</div>
                  <div className="info-tile-value" id="tlsIssuerVal">{auditData.tls.issuer_org || "Unknown CA"}</div>
                </div>
                <div className="info-tile">
                  <div className="info-tile-label">Expiration Countdown</div>
                  <div className="info-tile-value" id="tlsExpiryVal">
                    {auditData.tls.cert_expires_in_days} Days Remaining ({auditData.tls.expires_at})
                  </div>
                </div>
                <div className="info-tile">
                  <div className="info-tile-label">Subject Alternative Names (SANs)</div>
                  <div
                    className="info-tile-value"
                    id="tlsSansVal"
                    style={{ fontFamily: "var(--font-mono)", fontSize: "0.85rem" }}
                  >
                    {auditData.tls.sans_count} Domains (
                    {auditData.tls.sans_sample ? auditData.tls.sans_sample.slice(0, 3).join(", ") : ""}
                    ...)
                  </div>
                </div>
                <div className="info-tile">
                  <div className="info-tile-label">SHA-256 Fingerprint</div>
                  <div
                    className="info-tile-value"
                    id="tlsFingerprintVal"
                    style={{ fontFamily: "var(--font-mono)", fontSize: "0.74rem", cursor: "pointer" }}
                    title="Click to copy"
                    onClick={() => {
                      navigator.clipboard.writeText(auditData.tls.fingerprint_sha256);
                      alert("Fingerprint copied to clipboard!");
                    }}
                  >
                    {auditData.tls.fingerprint_sha256 || "N/A"}
                  </div>
                </div>
              </div>
            </div>

              </>
            )}

            {/* HTTP Security Headers Matrix */}
            <FindingsPanel
              findings={auditData.findings}
              manual={auditData.manual_checks}
              tier={auditData.tier}
              limitations={auditData.limitations}
            />

            {auditData.engine !== "OWASP ZAP" && (
              <>
            <div className="ember-card audit-card">
              <div className="audit-card-header">
                <div className="audit-card-title">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                    <polyline points="9 12 11 14 15 10" />
                  </svg>
                  HTTP Security Headers Defense Matrix
                </div>
              </div>

              {/* Missing Headers (Vulnerabilities) */}
              <div style={{ marginBottom: "2rem" }}>
                <div
                  className="info-tile-label"
                  style={{
                    marginBottom: "10px",
                    color: "var(--danger)",
                    display: "flex",
                    alignItems: "center",
                    gap: "8px",
                  }}
                >
                  <svg width="17" height="17" fill="none" stroke="currentColor" strokeWidth="2.2" viewBox="0 0 24 24" strokeLinecap="round" strokeLinejoin="round">
                    <polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2" />
                    <line x1="12" y1="8" x2="12" y2="12" />
                    <line x1="12" y1="16" x2="12.01" y2="16" />
                  </svg>
                  Missing Critical Policies (Action Required)
                </div>
                <div className="header-list" id="missingHeadersList">
                  {auditData.http.missing_headers && auditData.http.missing_headers.length > 0 ? (
                    auditData.http.missing_headers.map((item: any) => {
                      const sevClass =
                        item.severity === "Critical" || item.severity === "High"
                          ? "badge-danger"
                          : item.severity === "Medium"
                          ? "badge-warning"
                          : "badge-secure";
                      return (
                        <div key={item.name} className="header-item-row">
                          <div className="header-item-left">
                            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                              <span className="header-item-name" style={{ color: "var(--danger)" }}>
                                {item.name}
                              </span>
                              <span className={`status-badge ${sevClass}`}>{item.severity}</span>
                            </div>
                            <span className="header-item-desc">{item.description}</span>
                          </div>
                          <div className="header-item-actions">
                            <button
                              className="fix-btn"
                              onClick={() => openRemediation(item.name)}
                            >
                              <svg fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
                              </svg>
                              Fix Snippet
                            </button>
                          </div>
                        </div>
                      );
                    })
                  ) : (
                    <div className="header-item-row">
                      <span style={{ color: "var(--flame-orange)" }}>
                        All recommended enterprise security headers are enforced! 🎉
                      </span>
                    </div>
                  )}
                </div>
              </div>

              {/* Enforced Headers */}
              <div>
                <div
                  className="info-tile-label"
                  style={{
                    marginBottom: "10px",
                    color: "var(--flame-orange)",
                    display: "flex",
                    alignItems: "center",
                    gap: "8px",
                  }}
                >
                  <svg width="17" height="17" fill="none" stroke="currentColor" strokeWidth="2.2" viewBox="0 0 24 24" strokeLinecap="round" strokeLinejoin="round">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>
                  Enforced Security Policies
                </div>
                <div className="header-list" id="presentHeadersList">
                  {Object.keys(auditData.http.present_headers || {}).length > 0 ? (
                    Object.entries(auditData.http.present_headers).map(([k, val]: [string, any]) => (
                      <div key={k} className="header-item-row">
                        <div className="header-item-left">
                          <span className="header-item-name">{k}</span>
                        </div>
                        <div className="header-item-actions">
                          <span className="header-item-val">{val}</span>
                          <span className="status-badge badge-secure">PASSED</span>
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="header-item-row">
                      <span style={{ color: "var(--text-muted)" }}>
                        No standard security headers detected.
                      </span>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Server Information Leakage Card */}
            {auditData.http.leakage && auditData.http.leakage.length > 0 && (
              <div className="ember-card audit-card" id="leakageCard" style={{ display: "block" }}>
                <div className="audit-card-header">
                  <div className="audit-card-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                      <line x1="12" y1="9" x2="12" y2="13" />
                      <line x1="12" y1="17" x2="12.01" y2="17" />
                    </svg>
                    Information Disclosure & Server Banners
                  </div>
                  <span className="status-badge badge-warning">BANNER EXPOSED</span>
                </div>
                <div className="header-list" id="leakageList">
                  {auditData.http.leakage.map((leak: any, idx: number) => (
                    <div key={idx} className="header-item-row">
                      <div className="header-item-left">
                        <span className="header-item-name" style={{ color: "var(--warning)" }}>
                          {leak.header}: {leak.value}
                        </span>
                        <span className="header-item-desc">{leak.risk}</span>
                      </div>
                      <div className="header-item-actions">
                        <span className="status-badge badge-warning">DISCLOSED</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Cookie Security Audit Card */}
            {auditData.http.cookies && auditData.http.cookies.length > 0 && (
              <div className="ember-card audit-card" id="cookieCard" style={{ display: "block" }}>
                <div className="audit-card-header">
                  <div className="audit-card-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M12 2a10 10 0 1 0 10 10 4 4 0 0 1-5-5 4 4 0 0 1-5-5z" />
                      <circle cx="8.5" cy="8.5" r="1.5" fill="currentColor" />
                      <circle cx="15.5" cy="15.5" r="1.5" fill="currentColor" />
                      <circle cx="8.5" cy="15.5" r="1.5" fill="currentColor" />
                    </svg>
                    Cookie Security & Isolation Audit
                  </div>
                </div>
                <div className="header-list" id="cookieList">
                  {auditData.http.cookies.map((c: any, idx: number) => (
                    <div key={idx} className="header-item-row">
                      <div className="header-item-left">
                        <span className="header-item-name">{c.name}</span>
                        <span className="header-item-desc">
                          Scope: {c.domain || "Domain"} {c.path || "/"}
                        </span>
                      </div>
                      <div className="header-item-actions">
                        {c.secure ? (
                          <span className="status-badge badge-secure">Secure</span>
                        ) : (
                          <span className="status-badge badge-danger">Insecure</span>
                        )}
                        {c.httponly ? (
                          <span className="status-badge badge-secure">HttpOnly</span>
                        ) : (
                          <span className="status-badge badge-warning">No HttpOnly</span>
                        )}
                        <span className="status-badge badge-secure">SameSite={c.samesite}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

              </>
            )}

            {/* Threat Intelligence Export Suite */}
            <div className="ember-card audit-card">
              <div className="audit-card-header">
                <div className="audit-card-title">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                    <polyline points="16 18 22 12 16 6" />
                    <polyline points="8 6 2 12 8 18" />
                  </svg>
                  Threat Intelligence Export Suite
                </div>
              </div>
              <details className="technical-json-details">
                <summary>View technical JSON data</summary>
                <pre className="json-terminal" id="rawJsonOutput">{JSON.stringify(auditData, null, 2)}</pre>
              </details>
              <div className="action-btn-row">
                <button className="action-btn" id="copyJsonBtn" onClick={copyJson}>
                  <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
                    <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1" />
                  </svg>
                  {copyJsonText}
                </button>
                <button className="action-btn" id="downloadJsonBtn" onClick={downloadJson}>
                  <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                    <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
                    <polyline points="7 10 12 15 17 10" />
                    <line x1="12" y1="15" x2="12" y2="3" />
                  </svg>
                  Download JSON
                </button>
                <button className="action-btn" id="copyMarkdownBtn" onClick={copyMarkdown}>
                  <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                    <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" />
                    <polyline points="14 2 14 8 20 8" />
                    <line x1="16" y1="13" x2="8" y2="13" />
                    <line x1="16" y1="17" x2="8" y2="17" />
                  </svg>
                  {copyMdText}
                </button>
                <button className="action-btn" onClick={() => window.print()}>
                  <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                    <polyline points="6 9 6 2 18 2 18 9" />
                    <path d="M6 18H4a2 2 0 01-2-2v-5a2 2 0 012-2h16a2 2 0 012 2v5a2 2 0 01-2 2h-2" />
                    <rect x="6" y="14" width="12" height="8" />
                  </svg>
                  Print / PDF Report
                </button>
              </div>
            </div>
          </section>
        )}

        {/* Footer */}
        <footer className="site-footer">
          <p>
            <strong>CYBERSHIELD</strong> v3.0 — Elite Web Threat Intelligence & Cryptographic Assurance Platform · Developed for{" "}
            <a href="#" onClick={(e) => e.preventDefault()}>
              SecOps & Infrastructure Architects
            </a>
          </p>
        </footer>
      </main>

      {/* ═══════════ REMEDIATION GUIDE MODAL ═══════════ */}
      {remedModal.open && (
        <div
          className="modal-backdrop open"
          id="remedModal"
          onClick={() => setRemedModal((p) => ({ ...p, open: false }))}
        >
          <div
            className="modal-window ember-card"
            onClick={(e) => e.stopPropagation()}
          >
            <button
              className="modal-close-btn"
              onClick={() => {
                setRemedModal((p) => ({ ...p, open: false }));
              }}
            >
              <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                <line x1="18" y1="6" x2="6" y2="18" />
                <line x1="6" y1="6" x2="18" y2="18" />
              </svg>
            </button>
            <h3
              id="remedHeaderName"
              style={{
                fontSize: "1.4rem",
                fontWeight: 800,
                marginBottom: "6px",
                color: "var(--text-primary)",
                fontFamily: "var(--font-heading)",
              }}
            >
              {REMEDIATION_DB[remedModal.header]?.name || remedModal.header}
            </h3>
            <p
              id="remedHeaderDesc"
              style={{
                color: "var(--text-muted)",
                fontSize: "0.88rem",
                marginBottom: "1.35rem",
                lineHeight: 1.5,
              }}
            >
              {REMEDIATION_DB[remedModal.header]?.desc || "Security header configuration directives."}
            </p>

            <div className="remed-tab-row">
              {(["nginx", "apache", "cloudflare", "nextjs", "caddy"] as const).map((tab) => (
                <button
                  key={tab}
                  className={`remed-tab-btn ${remedModal.tab === tab ? "active" : ""}`}
                  onClick={() => {
                    setRemedModal((p) => ({ ...p, tab }));
                  }}
                >
                  {tab === "nextjs" ? "Next.js / Vercel" : tab.toUpperCase()}
                </button>
              ))}
            </div>

            <div className="code-box">
              <button className="code-copy-btn" id="remedCopyBtn" onClick={copyRemedSnippet}>
                {remedCopied ? "Copied!" : "Copy"}
              </button>
              <code id="remedCodeContent">
                {REMEDIATION_DB[remedModal.header]?.[remedModal.tab] ||
                  `// Add header ${remedModal.header} in server config`}
              </code>
            </div>
          </div>
        </div>
      )}

      {/* ═══════════ SCAN HISTORY DRAWER ═══════════ */}
      {isHistoryOpen && (
        <div
          className="drawer-backdrop open"
          id="historyDrawer"
          onClick={() => {
            setIsHistoryOpen(false);
          }}
        >
          <div
            className="drawer-panel"
            style={{ transform: "translateX(0)" }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="drawer-header">
              <div>
                <h3 style={{ fontSize: "1.3rem", fontWeight: 800, color: "var(--text-primary)", fontFamily: "var(--font-heading)" }}>
                  Audit History
                </h3>
                <p style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
                  Stored locally on this workstation
                </p>
              </div>
              <button
                className="modal-close-btn"
                style={{ position: "static" }}
                onClick={() => {
                  setIsHistoryOpen(false);
                }}
              >
                <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                  <line x1="18" y1="6" x2="6" y2="18" />
                  <line x1="6" y1="6" x2="18" y2="18" />
                </svg>
              </button>
            </div>

            <div className="drawer-list" id="historyList">
              {scanHistory.length === 0 ? (
                <div style={{ textAlign: "center", padding: "2rem 0", color: "var(--text-muted)" }}>
                  No scan history yet.
                </div>
              ) : (
                scanHistory.map((item, idx) => (
                  <div
                    key={idx}
                    className="drawer-item"
                    onClick={() => {
                      setAuditData(item);
                      setIsHistoryOpen(false);
                    }}
                  >
                    <div>
                      <div style={{ fontWeight: 700, color: "var(--text-primary)", fontSize: "0.95rem", fontFamily: "var(--font-heading)" }}>
                        {item.target}
                      </div>
                      <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                        {item.timestamp}
                      </div>
                    </div>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                      <span style={{ fontFamily: "var(--font-mono)", fontWeight: 800, fontSize: "1.1rem", color: item.grade_color }}>
                        {item.score}
                      </span>
                      <span className="status-badge" style={{ background: item.grade_color, color: "#070303", padding: "3px 8px" }}>
                        {item.grade}
                      </span>
                    </div>
                  </div>
                ))
              )}
            </div>

            <div style={{ marginTop: "1.5rem", display: "flex", justifyContent: "flex-end" }}>
              <button
                className="action-btn"
                onClick={clearHistory}
                style={{ color: "var(--danger)", borderColor: "rgba(255,34,63,0.35)" }}
              >
                Clear History
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ═══════════ SECOPS AUTH MODAL ═══════════ */}
      {authModal.open && (
        <div
          className="modal-backdrop open"
          id="authModal"
          onClick={() => setAuthModal((p) => ({ ...p, open: false }))}
        >
          <div
            className="modal-window ember-card"
            onClick={(e) => e.stopPropagation()}
          >
            <button
              className="modal-close-btn"
              onClick={() => {
                setAuthModal((p) => ({ ...p, open: false }));
              }}
            >
              <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                <line x1="18" y1="6" x2="6" y2="18" />
                <line x1="6" y1="6" x2="18" y2="18" />
              </svg>
            </button>
            <div style={{ textAlign: "center", marginBottom: "1rem" }}>
              <h3 style={{ fontSize: "1.5rem", fontWeight: 800, color: "var(--text-primary)", fontFamily: "var(--font-heading)" }}>
                SecOps Analyst Portal
              </h3>
              <p style={{ color: "var(--text-muted)", fontSize: "0.88rem" }}>
                Authenticate for elevated telemetry features
              </p>
            </div>

            <div className="auth-tab-row">
              <button
                className={`auth-tab-btn ${authModal.tab === "signin" ? "active" : ""}`}
                id="tabSignIn"
                onClick={() => {
                  setAuthModal((p) => ({ ...p, tab: "signin" }));
                }}
              >
                Sign In
              </button>
              <button
                className={`auth-tab-btn ${authModal.tab === "signup" ? "active" : ""}`}
                id="tabSignUp"
                onClick={() => {
                  setAuthModal((p) => ({ ...p, tab: "signup" }));
                }}
              >
                Create Account
              </button>
            </div>

            <form id="authForm" onSubmit={handleAuthSubmit}>
              {authModal.tab === "signup" && (
                <div className="auth-field" id="nameFieldGroup">
                  <label className="auth-label">Full Name</label>
                  <input
                    type="text"
                    id="authName"
                    className="auth-input-elem"
                    placeholder="Alex Morgan"
                    value={authName}
                    onChange={(e) => setAuthName(e.target.value)}
                  />
                </div>
              )}
              <div className="auth-field">
                <label className="auth-label">SecOps Email</label>
                <input
                  type="email"
                  id="authEmail"
                  className="auth-input-elem"
                  placeholder="analyst@cybershield.internal"
                  required
                  value={authEmail}
                  onChange={(e) => setAuthEmail(e.target.value)}
                />
              </div>
              <div className="auth-field">
                <label className="auth-label">Password</label>
                <input
                  type="password"
                  id="authPassword"
                  className="auth-input-elem"
                  placeholder="••••••••••••"
                  required
                  value={authPassword}
                  onChange={(e) => setAuthPassword(e.target.value)}
                />
              </div>
              <button type="submit" className="auth-submit-btn" id="authSubmitText">
                {authModal.tab === "signup" ? "Register SecOps Account" : "Access CyberShield Terminal"}
              </button>
            </form>
          </div>
        </div>
      )}
    </>
  );
}
