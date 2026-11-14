"use client";
import React from "react";
import type { Finding, ManualCheck } from "@/lib/findings";

const sevColor: Record<string, string> = {
  Critical: "var(--danger)", High: "var(--danger)", Medium: "#ffb703", Low: "var(--text-secondary)", Info: "var(--text-secondary)",
};
const confLabel: Record<string, string> = { confirmed: "Confirmed", likely: "Likely", manual: "Needs manual verification" };
/** Findings with confidence levels + guided manual checks. Tolerates old saved reports. */
export function FindingsPanel({ findings, manual, tier, limitations }: {
  findings?: Finding[]; manual?: ManualCheck[]; tier?: string; limitations?: string[];
}) {
  if (!findings) return null;
  return (
    <div className="ember-card audit-card" style={{ padding: 20 }}>
      <div style={{ display: "flex", justifyContent: "space-between", flexWrap: "wrap", gap: 8 }}>
        <strong>Findings ({findings.length}) — {tier === "deep" ? "Deep scan" : "Basic scan"}</strong>
        <span style={{ color: "var(--text-secondary)", fontSize: "0.85rem" }}>{tier === "deep" ? "Active checks · authorization attested" : "Passive checks only"}</span>
      </div>
      {findings.length === 0 && <p style={{ color: "var(--text-secondary)" }}>No findings from automated checks.</p>}
      {findings.map((f) => (
        <details key={f.id} style={{ borderTop: "1px solid rgba(255,255,255,0.08)", padding: "10px 0" }}>
          <summary style={{ cursor: "pointer" }}>
            <b style={{ color: sevColor[f.severity] }}>{f.severity}</b> · {f.title}
            <span style={{ color: "var(--text-secondary)", fontSize: "0.8rem" }}> · {confLabel[f.confidence]}</span>
          </summary>
          <div style={{ padding: "8px 0 0 12px", fontSize: "0.88rem" }}>
            <p><b>Evidence:</b> {f.evidence}</p>
            <p><b>Fix:</b> {f.remediation}</p>
            <p style={{ color: "var(--text-secondary)" }}>{f.cwe} · {f.owasp} · {f.wstg}</p>
          </div>
        </details>
      ))}
      {manual && manual.length > 0 && (
        <>
          <strong style={{ display: "block", marginTop: 18 }}>Guided manual checks ({manual.length})</strong>
          <p style={{ color: "var(--text-secondary)", fontSize: "0.85rem" }}>Automation cannot judge these. A tester should work through them on systems they are authorised to test.</p>
          {manual.map((m) => (
            <details key={m.id} style={{ borderTop: "1px solid rgba(255,255,255,0.08)", padding: "10px 0" }}>
              <summary style={{ cursor: "pointer" }}>{m.title} <span style={{ color: "var(--text-secondary)", fontSize: "0.8rem" }}>· {m.wstg}</span></summary>
              <div style={{ padding: "8px 0 0 12px", fontSize: "0.88rem" }}>
                <p><b>Why flagged:</b> {m.why}</p>
                <p><b>Needs:</b> {m.needs.join(", ")}</p>
                <ol style={{ paddingLeft: 18 }}>{m.steps.map((s, i) => <li key={i}>{s}</li>)}</ol>
              </div>
            </details>
          ))}
        </>
      )}
      {limitations && <ul style={{ color: "var(--text-secondary)", fontSize: "0.8rem", marginTop: 14, paddingLeft: 18 }}>{limitations.map((l, i) => <li key={i}>{l}</li>)}</ul>}
    </div>
  );
}
