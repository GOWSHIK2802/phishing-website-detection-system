import type { PhishingAnalysis } from "./phishing.functions";

function download(filename: string, content: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 500);
}

function baseName(a: PhishingAnalysis) {
  const host = (() => {
    try { return new URL(a.normalizedUrl).hostname; } catch { return "report"; }
  })();
  const ts = a.analyzedAt.replace(/[:.]/g, "-");
  return `phishguard-${host}-${ts}`;
}

export function exportJSON(a: PhishingAnalysis) {
  download(`${baseName(a)}.json`, JSON.stringify(a, null, 2), "application/json");
}

export function exportCSV(a: PhishingAnalysis) {
  const esc = (v: unknown) => `"${String(v ?? "").replace(/"/g, '""')}"`;
  const rows: string[] = [];
  rows.push(["field", "value"].map(esc).join(","));
  rows.push(["URL", a.url].map(esc).join(","));
  rows.push(["Normalized URL", a.normalizedUrl].map(esc).join(","));
  rows.push(["Analyzed At", a.analyzedAt].map(esc).join(","));
  rows.push(["Verdict", a.verdict].map(esc).join(","));
  rows.push(["Risk Score", a.score].map(esc).join(","));
  rows.push(["Confidence", a.confidence].map(esc).join(","));
  rows.push(["Summary", a.summary].map(esc).join(","));
  rows.push(["Recommendation", a.recommendation].map(esc).join(","));
  rows.push(["AI Explanation", a.aiExplanation].map(esc).join(","));
  rows.push(["Threat Intel Reported", a.threatIntel.reported].map(esc).join(","));
  rows.push(["Registrar", a.metadata.registrar].map(esc).join(","));
  rows.push(["Registration Date", a.metadata.registrationDate].map(esc).join(","));
  rows.push(["Expiration Date", a.metadata.expirationDate].map(esc).join(","));
  rows.push(["Domain Age (days)", a.metadata.domainAgeDays].map(esc).join(","));
  rows.push(["HTTPS", a.features.httpsStatus].map(esc).join(","));
  rows.push(["Threat Level", a.threatLevel ?? ""].map(esc).join(","));
  rows.push(["Scan Duration (ms)", a.scanDurationMs ?? ""].map(esc).join(","));
  rows.push(["IP Address", a.dns?.ipAddress ?? ""].map(esc).join(","));
  rows.push(["Hosting Country", a.dns?.hostingCountry ?? a.metadata.hostingCountry ?? ""].map(esc).join(","));
  rows.push(["DNS Status", a.dns?.status ?? ""].map(esc).join(","));
  if (a.threatServices?.length) {
    rows.push([""].map(esc).join(","));
    rows.push(["Intel Source", "Status", "Detail"].map(esc).join(","));
    for (const s of a.threatServices) rows.push([s.name, s.status, s.detail].map(esc).join(","));
  }
  rows.push([""].map(esc).join(","));
  rows.push(["Red Flag", "Explanation"].map(esc).join(","));
  for (const r of a.redFlags) rows.push([r.label, r.explanation].map(esc).join(","));
  rows.push([""].map(esc).join(","));
  rows.push(["Security Indicator", "Triggered", "Weight", "Detail"].map(esc).join(","));
  for (const h of a.heuristics) rows.push([h.label, h.triggered, h.weight, h.detail].map(esc).join(","));
  download(`${baseName(a)}.csv`, rows.join("\n"), "text/csv");
}

export function exportPDF(a: PhishingAnalysis) {
  // Open a print-friendly window and trigger the browser's PDF print dialog.
  const w = window.open("", "_blank", "width=900,height=1100");
  if (!w) return;
  const verdictColor = a.verdict === "dangerous" ? "#dc2626" : a.verdict === "suspicious" ? "#d97706" : "#059669";
  const flag = (f: { label: string; explanation: string }) =>
    `<li><strong>${escapeHtml(f.label)}</strong><br/><span style="color:#555">${escapeHtml(f.explanation)}</span></li>`;
  const heur = (h: PhishingAnalysis["heuristics"][number]) =>
    `<tr><td>${escapeHtml(h.label)}</td><td>${h.triggered ? "Yes" : "No"}</td><td>${h.weight}</td><td>${escapeHtml(h.detail)}</td></tr>`;
  w.document.write(`<!doctype html><html><head><meta charset="utf-8"><title>PhishGuard Report — ${escapeHtml(a.normalizedUrl)}</title>
<style>
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;padding:32px;color:#111;line-height:1.5;max-width:820px;margin:auto}
  h1{margin:0 0 4px}
  .badge{display:inline-block;padding:4px 12px;border-radius:999px;color:#fff;background:${verdictColor};font-size:12px;text-transform:uppercase;letter-spacing:.1em}
  .grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin:16px 0}
  .card{border:1px solid #e5e7eb;border-radius:8px;padding:12px}
  .k{color:#6b7280;font-size:12px;text-transform:uppercase;letter-spacing:.08em}
  table{width:100%;border-collapse:collapse;margin-top:8px;font-size:13px}
  th,td{border-bottom:1px solid #eee;padding:6px 8px;text-align:left;vertical-align:top}
  ul{padding-left:20px}
  small{color:#6b7280}
</style></head><body>
<h1>PhishGuard AI Report</h1>
<small>Generated ${new Date(a.analyzedAt).toLocaleString()}</small>
<p><span class="badge">${a.verdict}</span> &nbsp; Risk score <strong>${a.score}/100</strong> &nbsp; Confidence <strong>${a.confidence}%</strong> &nbsp; Threat level <strong>${escapeHtml(a.threatLevel ?? "n/a")}</strong>${a.scanDurationMs != null ? ` &nbsp; Scan took <strong>${(a.scanDurationMs / 1000).toFixed(2)}s</strong>` : ""}</p>
<div class="card"><div class="k">URL</div><div style="font-family:monospace;word-break:break-all">${escapeHtml(a.normalizedUrl)}</div></div>
<h3>Summary</h3><p>${escapeHtml(a.summary)}</p>
<h3>AI Explanation</h3><p>${escapeHtml(a.aiExplanation)}</p>
<h3>Security recommendation</h3><p>${escapeHtml(a.recommendation)}</p>
<h3>Website information</h3>
<div class="grid">
  <div class="card"><div class="k">Domain</div>${escapeHtml(a.metadata.registrableDomain)}</div>
  <div class="card"><div class="k">Registrar</div>${escapeHtml(a.metadata.registrar ?? "unknown")}</div>
  <div class="card"><div class="k">Registration</div>${escapeHtml(a.metadata.registrationDate ?? "unknown")}</div>
  <div class="card"><div class="k">Expiration</div>${escapeHtml(a.metadata.expirationDate ?? "unknown")}</div>
  <div class="card"><div class="k">Domain age (days)</div>${a.metadata.domainAgeDays ?? "unknown"}</div>
  <div class="card"><div class="k">IP address</div>${escapeHtml(a.dns?.ipAddress ?? "unresolved")}</div>
  <div class="card"><div class="k">Hosting country</div>${escapeHtml(a.dns?.hostingCountry ?? a.metadata.hostingCountry ?? "unknown")}</div>
  <div class="card"><div class="k">DNS status</div>${escapeHtml(a.dns?.status ?? "not checked")}</div>
  <div class="card"><div class="k">HTTPS</div>${a.features.httpsStatus ? "Yes" : "No"}</div>
  <div class="card"><div class="k">SSL certificate</div>${a.metadata.ssl.httpsReachable ? "Valid TLS handshake" : "Not verifiable"}</div>
  <div class="card"><div class="k">Threat feed</div>${a.threatIntel.reported ? `Reported (${escapeHtml(a.threatIntel.threat ?? "")})` : "Not reported"}</div>
</div>
${a.threatServices?.length ? `<h3>Threat intelligence</h3>
<table><thead><tr><th>Source</th><th>Status</th><th>Detail</th></tr></thead><tbody>
${a.threatServices.map((s) => `<tr><td>${escapeHtml(s.name)}</td><td>${escapeHtml(s.status)}</td><td>${escapeHtml(s.detail)}</td></tr>`).join("")}
</tbody></table>` : ""}
<h3>Red flags</h3><ul>${a.redFlags.map(flag).join("")}</ul>
<h3>Security indicators</h3>
<table><thead><tr><th>Indicator</th><th>Triggered</th><th>Weight</th><th>Detail</th></tr></thead><tbody>
${a.heuristics.map(heur).join("")}
</tbody></table>
<h3>URL feature breakdown</h3>
<table><tbody>
<tr><td>URL length</td><td>${a.features.urlLength}</td></tr>
<tr><td>Domain length</td><td>${a.features.domainLength}</td></tr>
<tr><td>Dots</td><td>${a.features.numDots}</td></tr>
<tr><td>Hyphens</td><td>${a.features.numHyphens}</td></tr>
<tr><td>Digits</td><td>${a.features.numDigits}</td></tr>
<tr><td>Special chars</td><td>${a.features.numSpecialChars}</td></tr>
<tr><td>Subdomains</td><td>${a.features.numSubdomains}</td></tr>
<tr><td>TLD</td><td>.${escapeHtml(a.features.tld)} (${a.features.tldType})</td></tr>
<tr><td>Entropy</td><td>${a.features.entropy}</td></tr>
<tr><td>Encoded chars</td><td>${a.features.encodedCharCount}</td></tr>
</tbody></table>
<script>window.onload=()=>setTimeout(()=>window.print(),300)</script>
</body></html>`);
  w.document.close();
}

function escapeHtml(s: string): string {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
