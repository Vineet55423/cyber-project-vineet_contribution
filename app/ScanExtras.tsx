"use client";
import React from "react";
import type { Finding, ManualCheck } from "@/lib/findings";

const sevColor: Record<string, string> = {
  Critical: "var(--danger)",
  High: "var(--danger)",
  Medium: "#ffb703",
  Low: "var(--text-secondary)",
  Info: "var(--text-secondary)",
  Informational: "var(--text-secondary)",
};
const confLabel: Record<string, string> = {
  confirmed: "Confirmed",
  likely: "Likely",
  manual: "Needs manual verification",
  "needs-manual-review": "Needs manual verification",
};

type ReportFinding = Partial<Finding> & {
  name?: string;
  risk?: string;
  description?: string;
  solution?: string;
  confidence?: string;
  evidence?: string;
};

function titleOf(f: ReportFinding) {
  return f.title || f.name || "Security observation";
}

function severityOf(f: ReportFinding) {
  const severity = f.severity || f.risk || "Informational";
  return severity === "Info" ? "Informational" : severity;
}

export function explainFinding(title: string, description?: string) {
  const text = `${title} ${description || ""}`.toLowerCase();
  if (text.includes("content-security-policy") || text.includes("content security policy") || text.includes("csp"))
    return "The website does not clearly limit which sources can run scripts or load content. A weak or missing rule can make some attacks easier.";
  if (text.includes("strict-transport-security") || text.includes("hsts"))
    return "The website is not telling browsers to always use a secure HTTPS connection on future visits.";
  if (text.includes("x-frame-options") || text.includes("clickjacking"))
    return "Another site may be able to embed this page and trick a visitor into clicking something they did not intend.";
  if (text.includes("x-content-type-options"))
    return "The website is not telling browsers to stick to the file types it declares, which can make unsafe content easier to misinterpret.";
  if (text.includes("cookie") && (text.includes("httponly") || text.includes("http only")))
    return "A cookie may be readable by page scripts. If it holds a login session, this can increase the impact of a script injection.";
  if (text.includes("cookie") && text.includes("secure"))
    return "A cookie may be sent over an unencrypted connection. Login or session cookies should only be sent over HTTPS.";
  if (text.includes("certificate") || text.includes("tls") || text.includes("ssl"))
    return "The secure connection or its certificate may be outdated, untrusted, or close to expiry. Visitors rely on it to protect data in transit.";
  if (text.includes("redirect") && text.includes("https"))
    return "Visitors may be able to reach the site over an unencrypted HTTP connection instead of being redirected to HTTPS.";
  if (text.includes("information disclosure") || text.includes("information leak") || text.includes("server header"))
    return "The server is revealing technical details that could help an attacker identify software or configuration to target.";
  if (text.includes("cross-origin") || text.includes("cors"))
    return "The site may allow other websites to read data from it. The allowed origins should be limited to trusted sites.";
  if (text.includes("sql injection"))
    return "The response may indicate that user input is being handled unsafely by a database. A developer should verify this before treating it as confirmed.";
  if (text.includes("cross site scripting") || text.includes("xss"))
    return "The scanner observed input reflected in a page. Check that the application safely encodes it so it cannot run as code.";
  return description || "The scanner found a condition that may affect the website's security. Review the observation and confirm it in context.";
}

function normalizeFindings(findings: ReportFinding[] = []) {
  return findings.map((raw, index) => {
    const title = titleOf(raw);
    const description = raw.description || raw.evidence;
    return {
      raw,
      key: raw.id || `${title}-${index}`,
      title,
      severity: severityOf(raw),
      meaning: explainFinding(title, description),
      evidence: raw.evidence || raw.description || "The scanner did not provide additional evidence.",
      recommendation: raw.remediation || raw.solution || "Review the affected component and apply a secure configuration.",
    };
  });
}

export function PlainLanguageSummary({ findings, checks, tier, target, score }: {
  findings?: ReportFinding[];
  checks?: { id: string; name: string; description?: string; status: "PASS" | "FAIL" | "NOT_RUN"; alert_count: number; evidence?: string[] }[];
  tier?: string;
  target?: string;
  score?: number;
}) {
  const items = normalizeFindings(findings || []);
  const counts = items.reduce<Record<string, number>>((result, item) => {
    result[item.severity] = (result[item.severity] || 0) + 1;
    return result;
  }, {});
  const urgent = (counts.Critical || 0) + (counts.High || 0);
  const headline = items.length === 0
    ? "The automated checks did not flag any issues."
    : urgent > 0
      ? `${urgent} high-priority ${urgent === 1 ? "issue needs" : "issues need"} attention.`
      : `${items.length} ${items.length === 1 ? "item was" : "items were"} flagged for review.`;

  return (
    <section className="ember-card audit-card plain-report" aria-label="Plain-language report summary">
      <div className="audit-card-header">
        <div>
          <div className="audit-card-title">Report in plain language</div>
          <p className="plain-report-lede">{target ? `For ${target}. ` : ""}{headline}</p>
        </div>
        <span className="status-badge badge-warning">{tier === "deep" ? "Deep scan" : "Basic scan"}</span>
      </div>
      <p>
        {tier === "deep"
          ? "This scan used active checks that send test requests to the site. Only run it on systems you are authorized to test."
          : "This scan reviewed publicly visible settings and responses without attempting to exploit the site."}
        {typeof score === "number"
          ? ` The score is ${score} out of 100; it is a summary indicator, not a guarantee that the site is safe.`
          : " An automated scan cannot prove that a site is completely safe."}
      </p>
      <div className="plain-report-counts" aria-label="Finding counts">
        {(["Critical", "High", "Medium", "Low", "Informational"] as const).map((level) => (
          <span key={level}><b>{counts[level] || 0}</b> {level}</span>
        ))}
      </div>
      {checks && checks.length > 0 && (
        <div className="plain-check-results">
          <strong>Five checks in this scan</strong>
          <ul>
            {checks.map((check) => (
              <li key={check.id}>
                <span className={`plain-check-status ${check.status.toLowerCase()}`}>
                  {check.status === "PASS" ? "No alert" : check.status === "FAIL" ? "Finding" : "Not run"}
                </span>
                <span><b>{check.name}:</b> {check.description}</span>
                {check.evidence?.map((line, index) => <small key={index}>{line}</small>)}
              </li>
            ))}
          </ul>
        </div>
      )}
      {items.length > 0 && (
        <ol className="plain-report-list">
          {items.slice(0, 5).map((item) => (
            <li key={item.key}>
              <strong>{item.title}</strong>
              <span>{item.meaning}</span>
              <small>Next step: {item.recommendation}</small>
            </li>
          ))}
        </ol>
      )}
      {items.length > 5 && <p className="plain-report-more">Showing the first 5 items here. See the full findings below.</p>}
    </section>
  );
}

/** Findings with clear explanations and technical references for engineers. */
export function FindingsPanel({ findings, manual, tier, limitations }: {
  findings?: ReportFinding[];
  manual?: ManualCheck[];
  tier?: string;
  limitations?: string[];
}) {
  if (!findings) return null;
  const items = normalizeFindings(findings);
  return (
    <div className="ember-card audit-card" style={{ padding: 20 }}>
      <div style={{ display: "flex", justifyContent: "space-between", flexWrap: "wrap", gap: 8 }}>
        <strong>Detailed findings ({findings.length}) — {tier === "deep" ? "Deep scan" : "Basic scan"}</strong>
        <span style={{ color: "var(--text-secondary)", fontSize: "0.85rem" }}>{tier === "deep" ? "Active checks" : "Passive checks"}</span>
      </div>
      {items.length === 0 && <p style={{ color: "var(--text-secondary)" }}>No findings from automated checks.</p>}
      {items.map(({ raw, key, title, severity, meaning, evidence, recommendation }) => (
        <details key={key} style={{ borderTop: "1px solid rgba(255,255,255,0.08)", padding: "10px 0" }}>
          <summary style={{ cursor: "pointer" }}>
            <b style={{ color: sevColor[severity] || "var(--text-secondary)" }}>{severity}</b> · {title}
            {raw.confidence && <span style={{ color: "var(--text-secondary)", fontSize: "0.8rem" }}> · {confLabel[raw.confidence] || `Scanner confidence: ${raw.confidence}`}</span>}
          </summary>
          <div style={{ padding: "8px 0 0 12px", fontSize: "0.88rem" }}>
            <p><b>What this means:</b> {meaning}</p>
            <p><b>What the scan observed:</b> {evidence}</p>
            <p><b>Recommended next step:</b> {recommendation}</p>
            {(raw.cwe || raw.owasp || raw.wstg) && (
              <p style={{ color: "var(--text-secondary)" }}>
                Technical references: {[raw.cwe, raw.owasp, raw.wstg].filter(Boolean).join(" · ")}
              </p>
            )}
          </div>
        </details>
      ))}
      {manual && manual.length > 0 && (
        <>
          <strong style={{ display: "block", marginTop: 18 }}>Checks that need a person ({manual.length})</strong>
          <p style={{ color: "var(--text-secondary)", fontSize: "0.85rem" }}>Automated checks cannot assess these reliably. A tester should review them only on systems they are authorized to test.</p>
          {manual.map((m) => (
            <details key={m.id} style={{ borderTop: "1px solid rgba(255,255,255,0.08)", padding: "10px 0" }}>
              <summary style={{ cursor: "pointer" }}>{m.title} <span style={{ color: "var(--text-secondary)", fontSize: "0.8rem" }}> · {m.wstg}</span></summary>
              <div style={{ padding: "8px 0 0 12px", fontSize: "0.88rem" }}>
                <p><b>Why this needs review:</b> {m.why}</p>
                <p><b>What is needed:</b> {m.needs.join(", ")}</p>
                <ol style={{ paddingLeft: 18 }}>{m.steps.map((step, i) => <li key={i}>{step}</li>)}</ol>
              </div>
            </details>
          ))}
        </>
      )}
      {limitations && <ul style={{ color: "var(--text-secondary)", fontSize: "0.8rem", marginTop: 14, paddingLeft: 18 }}>{limitations.map((limitation, i) => <li key={i}>{limitation}</li>)}</ul>}
    </div>
  );
}
