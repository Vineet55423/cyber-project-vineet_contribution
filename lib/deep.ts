/**
 * deep.ts — Node-side Sensitive File & Admin Discovery Probes
 *
 * As specified in the SecureScan ZAP architecture (Note #5):
 * ZAP handles runtime active tests (XSS, SQLi, Open Redirect, CORS), while
 * this Node module reliably handles sensitive file & admin discovery
 * (/.git/HEAD, /.env, phpinfo.php, /admin) via SSRF-safe requests.
 */
import { safeRequest } from "./guard";
import { OWASP, type Finding, type Signals } from "./findings";

export async function runDeepChecks(
  _baseUrl: string,
  hostname: string,
  html: string
): Promise<{ findings: Finding[]; signals: Signals }> {
  const findings: Finding[] = [];
  let n = 1;
  const add = (x: Omit<Finding, "id" | "tier">) =>
    findings.push({ id: `CS-D-${String(n++).padStart(3, "0")}`, tier: "deep", ...x });

  const origin = `https://${hostname}`;
  const get = async (path: string) => {
    try {
      return await safeRequest(origin + path, {
        method: "GET",
        sameHostOnly: true,
        followRedirects: false,
        maxBytes: 64 * 1024,
        timeoutMs: 3500,
      });
    } catch {
      return null;
    }
  };

  // Run sensitive file & admin discovery probes concurrently
  const [gitRes, envRes, infoRes, adminRes] = await Promise.allSettled([
    get("/.git/HEAD"),
    get("/.env"),
    get("/phpinfo.php"),
    get("/admin"),
  ]);

  const git = gitRes.status === "fulfilled" ? gitRes.value : null;
  const env = envRes.status === "fulfilled" ? envRes.value : null;
  const info = infoRes.status === "fulfilled" ? infoRes.value : null;
  const admin = adminRes.status === "fulfilled" ? adminRes.value : null;

  // 1. Exposed Git metadata
  if (git && git.status === 200 && /^ref:\s*refs\//.test(git.body.trim())) {
    add({
      title: "Git repository metadata exposed",
      severity: "Critical",
      confidence: "confirmed",
      evidence: "/.git/HEAD returned a valid git ref.",
      cwe: "CWE-538",
      owasp: OWASP.A05,
      wstg: "WSTG-CONF-04",
      remediation: "Block access to /.git at the web server / reverse proxy level.",
    });
  }

  // 2. Exposed .env configuration
  if (
    env &&
    env.status === 200 &&
    !/html/i.test(env.headers["content-type"] || "") &&
    /^[A-Z][A-Z0-9_]{2,}=.+/m.test(env.body)
  ) {
    add({
      title: "Environment configuration file (.env) exposed",
      severity: "Critical",
      confidence: "confirmed",
      evidence: "/.env returned KEY=VALUE configuration secrets.",
      cwe: "CWE-538",
      owasp: OWASP.A05,
      wstg: "WSTG-CONF-04",
      remediation: "Remove the .env file from the web server public document root immediately and rotate exposed secrets.",
    });
  }

  // 3. Exposed phpinfo
  if (info && info.status === 200 && /<title>phpinfo\(\)<\/title>|PHP Version/i.test(info.body)) {
    add({
      title: "PHP configuration info (phpinfo) publicly exposed",
      severity: "Medium",
      confidence: "confirmed",
      evidence: "/phpinfo.php returned system environment and PHP version configuration.",
      cwe: "CWE-200",
      owasp: OWASP.A05,
      wstg: "WSTG-INFO-08",
      remediation: "Delete or restrict access to diagnostic phpinfo files in production.",
    });
  }

  // 4. Exposed Admin portal
  if (admin && [200, 401, 403].includes(admin.status) && !/404/i.test(admin.body)) {
    add({
      title: "Administrative console endpoint discovered",
      severity: "Low",
      confidence: "likely",
      evidence: `/admin responded with HTTP ${admin.status}.`,
      cwe: "CWE-284",
      owasp: OWASP.A01,
      wstg: "WSTG-CONF-05",
      remediation: "Ensure the administration portal requires multi-factor authentication and IP allowlisting.",
    });
  }

  // Compute DOM signals for manual checklist
  const signals: Signals = {
    hasPasswordForm: /type=["']password["']/i.test(html),
    hasFileUpload: /type=["']file["']/i.test(html),
    reflectsInput: false,
    hasForms: /<form[\s>]/i.test(html),
  };

  return { findings, signals };
}
