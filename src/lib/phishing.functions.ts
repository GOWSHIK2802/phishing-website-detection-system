import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";

const InputSchema = z.object({
  url: z.string().trim().min(1),
});

export type PhishingVerdict = "safe" | "suspicious" | "dangerous";

export interface UrlFeatures {
  urlLength: number;
  domainLength: number;
  numDots: number;
  numHyphens: number;
  numDigits: number;
  numSpecialChars: number;
  numSubdomains: number;
  httpsStatus: boolean;
  tld: string;
  tldType: "common" | "country" | "suspicious" | "other";
  entropy: number;
  encodedCharCount: number;
}

export interface DomainMetadata {
  registrableDomain: string;
  registrar: string | null;
  registrationDate: string | null;
  expirationDate: string | null;
  domainAgeDays: number | null;
  daysUntilExpiry: number | null;
  hostingCountry: string | null;
  nameservers: string[];
  ssl: {
    httpsReachable: boolean;
    status: number | null;
    error: string | null;
  };
  redirectChain: string[];
  fetchedAt: string;
  source: string;
}

export interface ThreatIntel {
  checked: boolean;
  source: string;
  reported: boolean;
  threat: string | null;
  firstSeen: string | null;
  lastSeen: string | null;
  reference: string | null;
  error: string | null;
}

export interface FeatureContribution {
  feature: string;
  contribution: number; // 0-100 relative importance
  direction: "risk" | "safe";
  explanation: string;
}

export interface PhishingAnalysis {
  url: string;
  normalizedUrl: string;
  score: number;
  confidence: number; // 0-100
  verdict: PhishingVerdict;
  summary: string;
  redFlags: { label: string; explanation: string }[];
  greenFlags: string[];
  recommendation: string;
  recommendations: string[];
  heuristics: {
    label: string;
    detail: string;
    weight: "low" | "medium" | "high";
    triggered: boolean;
    explanation: string;
  }[];
  features: UrlFeatures;
  metadata: DomainMetadata;
  threatIntel: ThreatIntel;
  featureImportance: FeatureContribution[];
  aiExplanation: string;
  analyzedAt: string;
}

function normalize(raw: string): string {
  let u = raw.trim();
  if (!/^https?:\/\//i.test(u)) u = "https://" + u;
  return u;
}

function shannonEntropy(s: string): number {
  const freq: Record<string, number> = {};
  for (const ch of s) freq[ch] = (freq[ch] ?? 0) + 1;
  const len = s.length || 1;
  let h = 0;
  for (const k in freq) {
    const p = freq[k] / len;
    h -= p * Math.log2(p);
  }
  return Math.round(h * 100) / 100;
}

function levenshtein(a: string, b: string): number {
  const m = a.length, n = b.length;
  if (!m) return n;
  if (!n) return m;
  const dp = Array.from({ length: m + 1 }, (_, i) => [i, ...Array(n).fill(0)]);
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++)
    for (let j = 1; j <= n; j++)
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1),
      );
  return dp[m][n];
}

const BRANDS = [
  "paypal","apple","microsoft","google","amazon","facebook","instagram",
  "netflix","wellsfargo","chase","amex","coinbase","binance","metamask",
  "outlook","office365","dhl","fedex","usps","github","linkedin","dropbox",
  "adobe","spotify","twitter","whatsapp","tiktok",
];
const COMMON_TLDS = new Set(["com","org","net","edu","gov","io","co","us","uk","de","fr","jp","ca","au"]);
const COUNTRY_TLDS = new Set(["us","uk","de","fr","jp","ca","au","in","cn","br","ru","es","it","nl"]);
const SUSPICIOUS_TLDS = [".zip",".mov",".tk",".ml",".ga",".cf",".gq",".top",".xyz",".click",".country",".work",".rest"];
const SHORTENERS = ["bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly","rebrand.ly","cutt.ly","shorturl.at"];
const SUSPICIOUS_KEYWORDS = ["login","verify","update","secure","account","wallet","signin","confirm","banking","password","suspended","limited","validate"];

function computeFeatures(url: URL): UrlFeatures {
  const host = url.hostname.toLowerCase();
  const full = url.href;
  const parts = host.split(".");
  const tld = parts[parts.length - 1];
  const tldType: UrlFeatures["tldType"] =
    SUSPICIOUS_TLDS.includes("." + tld) ? "suspicious" :
    COMMON_TLDS.has(tld) ? "common" :
    COUNTRY_TLDS.has(tld) ? "country" : "other";

  return {
    urlLength: full.length,
    domainLength: host.length,
    numDots: (host.match(/\./g) || []).length,
    numHyphens: (host.match(/-/g) || []).length,
    numDigits: (host.match(/\d/g) || []).length,
    numSpecialChars: (full.match(/[^a-zA-Z0-9:/?.&=_\-#%]/g) || []).length,
    numSubdomains: Math.max(0, parts.length - 2),
    httpsStatus: url.protocol === "https:",
    tld,
    tldType,
    entropy: shannonEntropy(host),
    encodedCharCount: (full.match(/%[0-9a-fA-F]{2}/g) || []).length,
  };
}

function detectTyposquat(registrable: string): { detected: boolean; brand: string | null; distance: number } {
  const base = registrable.split(".")[0];
  for (const b of BRANDS) {
    const d = levenshtein(base, b);
    if (d > 0 && d <= 2 && base !== b) return { detected: true, brand: b, distance: d };
  }
  return { detected: false, brand: null, distance: 0 };
}

function runHeuristics(rawUrl: string, features: UrlFeatures) {
  const url = new URL(rawUrl);
  const host = url.hostname.toLowerCase();
  const path = url.pathname + url.search;
  const full = url.href;
  const parts = host.split(".");
  const registrable = parts.slice(-2).join(".");

  const hasIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
  const isPunycode = host.includes("xn--");
  const isHttps = url.protocol === "https:";
  const hasPort = !!url.port && url.port !== "80" && url.port !== "443";
  const hasAtSymbol = full.includes("@");
  const hasCredsInPath = new RegExp(`(${SUSPICIOUS_KEYWORDS.join("|")})`, "i").test(path);
  const brandInSubdomainOrPath = BRANDS.some(
    (b) => (parts.slice(0, -2).join(".").includes(b) || path.toLowerCase().includes(b)) && !registrable.includes(b),
  );
  const suspiciousTld = features.tldType === "suspicious";
  const isShortener = SHORTENERS.includes(registrable);
  const longUrl = features.urlLength > 100;
  const manyDigits = features.numDigits >= 4;
  const highEntropy = features.entropy > 4.0;
  const hasEncoded = features.encodedCharCount >= 2;
  const typo = detectTyposquat(registrable);

  const items = [
    { label: "IP address as host", detail: `Host is ${host}`, weight: "high" as const, triggered: hasIp,
      explanation: "Legitimate sites use domain names. A raw IP is a strong sign of a phishing kit hosted on a cheap server." },
    { label: "Punycode / IDN homograph", detail: "Hostname contains xn-- (unicode disguise)", weight: "high" as const, triggered: isPunycode,
      explanation: "Attackers use lookalike Unicode letters (e.g. Cyrillic 'а') to imitate real brand names." },
    { label: "No HTTPS", detail: `Protocol is ${url.protocol}`, weight: "medium" as const, triggered: !isHttps,
      explanation: "Plain HTTP is unencrypted. Real login pages always use HTTPS." },
    { label: "Uses URL shortener", detail: `${registrable} hides the true destination`, weight: "medium" as const, triggered: isShortener,
      explanation: "Shorteners mask the real URL — attackers use them to bypass filters and hide the destination." },
    { label: "Suspicious TLD", detail: `.${features.tld} is commonly abused`, weight: "medium" as const, triggered: suspiciousTld,
      explanation: "Free or cheap TLDs are heavily used in phishing campaigns because they are disposable." },
    { label: "Brand name in subdomain or path", detail: "Impersonation pattern", weight: "high" as const, triggered: brandInSubdomainOrPath,
      explanation: "Placing a known brand in a subdomain or path (paypal.example.com) tricks users into trusting the URL." },
    { label: "Deep subdomain nesting", detail: `${features.numSubdomains} subdomain levels`, weight: "low" as const, triggered: features.numSubdomains >= 3,
      explanation: "Excessive subdomains can hide the true registered domain from casual inspection." },
    { label: "Excessive hyphens in host", detail: `${features.numHyphens} hyphens`, weight: "low" as const, triggered: features.numHyphens >= 3,
      explanation: "Many hyphens are common in throwaway phishing domains like 'apple-id-verify-secure'." },
    { label: "@ symbol in URL", detail: "Can mask the real host", weight: "high" as const, triggered: hasAtSymbol,
      explanation: "Browsers treat everything before '@' as user info and ignore it — attackers exploit this to fake the domain." },
    { label: "Sensitive action words in path", detail: "login/verify/secure/update present", weight: "low" as const, triggered: hasCredsInPath,
      explanation: "Phishing pages typically live at URLs promising to 'verify', 'secure' or 'update' something." },
    { label: "Non-standard port", detail: `Port ${url.port}`, weight: "medium" as const, triggered: hasPort,
      explanation: "Real login pages don't use unusual ports; this often means a self-hosted attacker box." },
    { label: "Very long URL", detail: `${features.urlLength} characters`, weight: "low" as const, triggered: longUrl,
      explanation: "Very long URLs are used to bury the real destination past the visible portion of the address bar." },
    { label: "Digit-heavy hostname", detail: "Many numeric characters in host", weight: "low" as const, triggered: manyDigits,
      explanation: "Algorithmically generated phishing domains often mix in many digits." },
    { label: "High-entropy hostname", detail: `Entropy ${features.entropy}`, weight: "low" as const, triggered: highEntropy,
      explanation: "Random-looking hostnames are often auto-generated by phishing infrastructure." },
    { label: "URL-encoded characters", detail: `${features.encodedCharCount} %XX sequences`, weight: "medium" as const, triggered: hasEncoded,
      explanation: "Encoded characters can hide malicious payloads or keywords from simple filters." },
    { label: "Typosquatting suspected", detail: typo.brand ? `Looks like '${typo.brand}' (distance ${typo.distance})` : "None", weight: "high" as const, triggered: typo.detected,
      explanation: "The domain is one or two edits away from a real brand — a classic typosquatting attack." },
  ];

  const weightMap = { low: 6, medium: 14, high: 22 } as const;
  let score = 0;
  for (const h of items) if (h.triggered) score += weightMap[h.weight];
  score = Math.min(100, score);

  return { heuristics: items, score, host, registrable, typo };
}

async function fetchWithTimeout(url: string, init: RequestInit & { timeoutMs?: number } = {}) {
  const { timeoutMs = 5000, ...rest } = init;
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetch(url, { ...rest, signal: ctrl.signal });
  } finally {
    clearTimeout(t);
  }
}

async function fetchMetadata(url: URL, registrable: string): Promise<DomainMetadata> {
  const meta: DomainMetadata = {
    registrableDomain: registrable,
    registrar: null,
    registrationDate: null,
    expirationDate: null,
    domainAgeDays: null,
    daysUntilExpiry: null,
    hostingCountry: null,
    nameservers: [],
    ssl: { httpsReachable: false, status: null, error: null },
    redirectChain: [],
    fetchedAt: new Date().toISOString(),
    source: "RDAP (rdap.org) + HEAD probe",
  };

  // RDAP lookup for WHOIS-like info
  try {
    const r = await fetchWithTimeout(`https://rdap.org/domain/${registrable}`, { timeoutMs: 4500 });
    if (r.ok) {
      const j: any = await r.json();
      const events: any[] = j.events ?? [];
      const reg = events.find((e) => e.eventAction === "registration");
      const exp = events.find((e) => e.eventAction === "expiration");
      meta.registrationDate = reg?.eventDate ?? null;
      meta.expirationDate = exp?.eventDate ?? null;
      const registrarEntity = (j.entities ?? []).find((e: any) => (e.roles ?? []).includes("registrar"));
      if (registrarEntity) {
        const vcard = registrarEntity.vcardArray?.[1] ?? [];
        const fn = vcard.find((f: any) => f[0] === "fn");
        meta.registrar = fn?.[3] ?? registrarEntity.handle ?? null;
      }
      meta.nameservers = (j.nameservers ?? []).map((n: any) => n.ldhName).filter(Boolean);
      const now = Date.now();
      if (meta.registrationDate) meta.domainAgeDays = Math.floor((now - new Date(meta.registrationDate).getTime()) / 86400000);
      if (meta.expirationDate) meta.daysUntilExpiry = Math.floor((new Date(meta.expirationDate).getTime() - now) / 86400000);
    }
  } catch {
    // ignore
  }

  // HTTPS reachability + redirects
  try {
    const chain: string[] = [];
    let current = url.href;
    for (let i = 0; i < 4; i++) {
      const r = await fetchWithTimeout(current, { method: "HEAD", redirect: "manual", timeoutMs: 4000 });
      chain.push(`${r.status} ${current}`);
      meta.ssl.status = r.status;
      meta.ssl.httpsReachable = current.startsWith("https:");
      const loc = r.headers.get("location");
      const country = r.headers.get("cf-ipcountry") || r.headers.get("x-country-code");
      if (country && !meta.hostingCountry) meta.hostingCountry = country;
      if (loc && r.status >= 300 && r.status < 400) {
        current = new URL(loc, current).href;
        continue;
      }
      break;
    }
    meta.redirectChain = chain;
  } catch (err) {
    meta.ssl.error = err instanceof Error ? err.message : String(err);
  }

  return meta;
}

async function fetchThreatIntel(url: string): Promise<ThreatIntel> {
  const intel: ThreatIntel = {
    checked: false,
    source: "URLhaus (abuse.ch)",
    reported: false,
    threat: null,
    firstSeen: null,
    lastSeen: null,
    reference: null,
    error: null,
  };
  try {
    const body = new URLSearchParams({ url });
    const r = await fetchWithTimeout("https://urlhaus-api.abuse.ch/v1/url/", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
      timeoutMs: 4500,
    });
    intel.checked = true;
    if (r.ok) {
      const j: any = await r.json();
      if (j.query_status === "ok") {
        intel.reported = true;
        intel.threat = j.threat ?? "malware_download";
        intel.firstSeen = j.date_added ?? null;
        intel.lastSeen = j.last_online ?? null;
        intel.reference = j.urlhaus_reference ?? null;
      }
    }
  } catch (err) {
    intel.error = err instanceof Error ? err.message : String(err);
  }
  return intel;
}

function computeFeatureImportance(
  heuristics: PhishingAnalysis["heuristics"],
  features: UrlFeatures,
  intel: ThreatIntel,
): FeatureContribution[] {
  const weightMap = { low: 6, medium: 14, high: 22 } as const;
  const contribs: FeatureContribution[] = [];
  for (const h of heuristics) {
    if (h.triggered) {
      contribs.push({
        feature: h.label,
        contribution: weightMap[h.weight],
        direction: "risk",
        explanation: h.explanation,
      });
    }
  }
  if (features.httpsStatus) contribs.push({ feature: "HTTPS enabled", contribution: 8, direction: "safe", explanation: "Encrypted transport is present." });
  if (features.tldType === "common") contribs.push({ feature: "Common TLD", contribution: 6, direction: "safe", explanation: "TLD is a well-established one (.com/.org/etc.)." });
  if (intel.reported) contribs.push({ feature: "Listed on threat feed", contribution: 40, direction: "risk", explanation: "URLhaus has an active record for this URL." });
  return contribs.sort((a, b) => b.contribution - a.contribution).slice(0, 8);
}

function buildRecommendations(verdict: PhishingVerdict, features: UrlFeatures, intel: ThreatIntel): string[] {
  const recs: string[] = [];
  if (verdict !== "safe") {
    recs.push("Do not enter your credentials, payment info, or personal data on this page.");
    recs.push("Verify the destination by typing the official domain into your browser directly.");
  }
  if (!features.httpsStatus) recs.push("Avoid submitting any information — this URL does not use HTTPS.");
  if (intel.reported) recs.push("This URL is on a public threat feed — treat it as actively malicious.");
  recs.push("Check that the SSL certificate matches the expected organization.");
  recs.push("If you believe this is phishing, report it to the impersonated brand and to Google Safe Browsing.");
  if (verdict === "safe") recs.push("Even safe-looking URLs can be compromised — always double-check before signing in.");
  return recs;
}

export const analyzeUrl = createServerFn({ method: "POST" })
  .inputValidator((data: unknown) => InputSchema.parse(data))
  .handler(async ({ data }): Promise<PhishingAnalysis> => {
    const apiKey = process.env.LOVABLE_API_KEY;
    if (!apiKey) throw new Error("Missing LOVABLE_API_KEY");

    let normalizedUrl: string;
    let parsedUrl: URL;
    try {
      normalizedUrl = normalize(data.url);
      parsedUrl = new URL(normalizedUrl);
    } catch {
      throw new Error("That doesn't look like a valid URL.");
    }

    const features = computeFeatures(parsedUrl);
    const { heuristics, score: heuristicScore, host, registrable } = runHeuristics(normalizedUrl, features);
    const triggered = heuristics.filter((h) => h.triggered);

    // Parallel external lookups
    const [metadata, threatIntel] = await Promise.all([
      fetchMetadata(parsedUrl, registrable),
      fetchThreatIntel(normalizedUrl),
    ]);

    const systemPrompt = `You are a cybersecurity analyst specializing in phishing detection. You analyze URLs from their string, structure, heuristic signals, WHOIS/RDAP metadata, and threat-intel feeds. You NEVER visit URLs. Be concise, factual, and cautious.`;

    const userPrompt = `Analyze this URL for phishing risk.

URL: ${normalizedUrl}
Host: ${host}
Registrable domain: ${registrable}
Domain age (days): ${metadata.domainAgeDays ?? "unknown"}
Registrar: ${metadata.registrar ?? "unknown"}
Expires: ${metadata.expirationDate ?? "unknown"}
HTTPS reachable: ${metadata.ssl.httpsReachable}
Redirect chain: ${metadata.redirectChain.join(" -> ") || "none"}
Threat intel (URLhaus): ${threatIntel.reported ? `REPORTED (${threatIntel.threat})` : "not reported"}

Heuristic signals (${triggered.length}/${heuristics.length} triggered):
${heuristics.map((h) => `- [${h.triggered ? "X" : " "}] (${h.weight}) ${h.label}: ${h.detail}`).join("\n")}

Preliminary heuristic score: ${heuristicScore}/100

Return ONLY a JSON object with:
- "score": integer 0-100 (final risk)
- "confidence": integer 0-100 (how sure you are)
- "verdict": "safe" | "suspicious" | "dangerous"
- "summary": 1-2 sentence plain-English verdict
- "redFlags": array of 2-6 objects {"label": string, "explanation": string} — plain-language reasons
- "greenFlags": array of 0-4 strings
- "recommendation": one sentence primary action
- "aiExplanation": 2-4 sentences explaining WHY the model reached this verdict, referencing specific features

No markdown, no code fences.`;

    const response = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Lovable-API-Key": apiKey },
      body: JSON.stringify({
        model: "google/gemini-3-flash-preview",
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: userPrompt },
        ],
        response_format: { type: "json_object" },
      }),
    });

    if (response.status === 429) throw new Error("Rate limit reached. Please try again in a moment.");
    if (response.status === 402) throw new Error("AI credits exhausted. Please add credits in Lovable Cloud.");
    if (!response.ok) {
      const text = await response.text().catch(() => "");
      throw new Error(`AI gateway error (${response.status}): ${text.slice(0, 200)}`);
    }

    const payload = await response.json();
    const content: string = payload?.choices?.[0]?.message?.content ?? "{}";

    let parsed: any;
    try {
      parsed = JSON.parse(content);
    } catch {
      const match = content.match(/\{[\s\S]*\}/);
      parsed = match ? JSON.parse(match[0]) : {};
    }

    let score = Math.max(0, Math.min(100, Math.round(parsed.score ?? heuristicScore)));
    if (threatIntel.reported) score = Math.max(score, 90);

    const verdict: PhishingVerdict =
      parsed.verdict ?? (score >= 65 ? "dangerous" : score >= 30 ? "suspicious" : "safe");

    const confidence = Math.max(0, Math.min(100, Math.round(parsed.confidence ?? (60 + triggered.length * 4))));

    const redFlagsRaw = parsed.redFlags ?? [];
    const redFlags = Array.isArray(redFlagsRaw)
      ? redFlagsRaw.map((r: any) =>
          typeof r === "string"
            ? { label: r, explanation: "" }
            : { label: String(r.label ?? ""), explanation: String(r.explanation ?? "") },
        )
      : [];

    const featureImportance = computeFeatureImportance(heuristics, features, threatIntel);
    const recommendations = buildRecommendations(verdict, features, threatIntel);

    return {
      url: data.url,
      normalizedUrl,
      score,
      confidence,
      verdict,
      summary: parsed.summary ?? "No summary available.",
      redFlags: redFlags.length
        ? redFlags
        : triggered
            .filter((h) => h.weight !== "low")
            .map((h) => ({ label: h.label, explanation: h.explanation })),
      greenFlags: parsed.greenFlags ?? [],
      recommendation:
        parsed.recommendation ??
        (verdict === "safe"
          ? "This URL looks fine, but always double-check before entering credentials."
          : "Do not enter any personal information or credentials on this site."),
      recommendations,
      heuristics,
      features,
      metadata,
      threatIntel,
      featureImportance,
      aiExplanation: parsed.aiExplanation ?? parsed.summary ?? "",
      analyzedAt: new Date().toISOString(),
    };
  });
