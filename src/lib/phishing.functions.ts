import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { predict, XGB_METRICS, XGB_GAIN, type XgbPrediction } from "./xgboost";

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

export interface DnsInfo {
  resolved: boolean;
  status: string;
  ipAddress: string | null;
  ipAddresses: string[];
  hostingCountry: string | null;
  hostingOrg: string | null;
}

export type ServiceStatus = "safe" | "detected" | "unavailable" | "info";

export interface ThreatService {
  name: string;
  status: ServiceStatus;
  detail: string;
  checkedAt: string;
}

export type ThreatLevel = "low" | "medium" | "high" | "critical";

export interface FeatureContribution {
  feature: string;
  contribution: number; // 0-100 relative importance
  direction: "risk" | "safe";
  explanation: string;
}


export interface ModelInfo {
  name: string;
  algorithm: string;
  objective: string;
  rounds: number;
  maxDepth: number;
  learningRate: number;
  trainedOn: number;
  accuracy: number;
  auc: number;
  probability: number; // 0-1 phishing probability from the ensemble
  margin: number; // raw log-odds
  topGain: { feature: string; gain: number }[];
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
  model: ModelInfo;
  aiExplanation: string;
  analyzedAt: string;
  dns?: DnsInfo;
  threatServices?: ThreatService[];
  scanDurationMs?: number;
  threatLevel?: ThreatLevel;
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

/** DNS-over-HTTPS resolution + IP geolocation (no API keys required). */
async function fetchDns(host: string): Promise<DnsInfo> {
  const info: DnsInfo = {
    resolved: false,
    status: "unresolved",
    ipAddress: null,
    ipAddresses: [],
    hostingCountry: null,
    hostingOrg: null,
  };
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) {
    info.resolved = true;
    info.status = "literal IP (no DNS record)";
    info.ipAddress = host;
    info.ipAddresses = [host];
  } else {
    try {
      const r = await fetchWithTimeout(`https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`, {
        timeoutMs: 4000,
        headers: { accept: "application/dns-json" },
      });
      if (r.ok) {
        const j: any = await r.json();
        const answers: any[] = j.Answer ?? [];
        const ips = answers.filter((a) => a.type === 1).map((a) => String(a.data));
        info.ipAddresses = ips;
        info.ipAddress = ips[0] ?? null;
        info.resolved = ips.length > 0;
        info.status = ips.length > 0 ? "resolved (NOERROR)" : j.Status === 3 ? "NXDOMAIN — domain does not resolve" : "no A record";
      }
    } catch {
      info.status = "lookup failed";
    }
  }

  if (info.ipAddress) {
    try {
      const g = await fetchWithTimeout(`https://ipwho.is/${info.ipAddress}`, { timeoutMs: 4000 });
      if (g.ok) {
        const j: any = await g.json();
        if (j.success !== false) {
          info.hostingCountry = j.country ?? null;
          info.hostingOrg = j.connection?.org ?? j.connection?.isp ?? null;
        }
      }
    } catch {
      // ignore
    }
  }
  return info;
}

function buildThreatServices(
  metadata: DomainMetadata,
  dns: DnsInfo,
  intel: ThreatIntel,
  features: UrlFeatures,
): ThreatService[] {
  const at = new Date().toISOString();
  return [
    {
      name: "WHOIS / RDAP",
      status: metadata.registrar || metadata.registrationDate ? "info" : "unavailable",
      detail: metadata.registrar
        ? `${metadata.registrar}${metadata.domainAgeDays !== null ? ` · domain ${metadata.domainAgeDays} days old` : ""}`
        : "No registration record returned",
      checkedAt: at,
    },
    {
      name: "DNS lookup",
      status: dns.resolved ? "safe" : "unavailable",
      detail: dns.resolved ? `${dns.status} → ${dns.ipAddress}` : dns.status,
      checkedAt: at,
    },
    {
      name: "SSL certificate",
      status: features.httpsStatus && metadata.ssl.httpsReachable ? "safe" : "unavailable",
      detail: metadata.ssl.httpsReachable
        ? `Valid TLS handshake (HTTP ${metadata.ssl.status ?? "—"})`
        : metadata.ssl.error ?? "HTTPS endpoint not reachable",
      checkedAt: at,
    },
    {
      name: "URLhaus (abuse.ch)",
      status: intel.reported ? "detected" : intel.checked ? "safe" : "unavailable",
      detail: intel.reported ? `Listed as ${intel.threat ?? "malicious"}` : intel.checked ? "Not present on feed" : "Feed unreachable",
      checkedAt: at,
    },
    {
      name: "Google Safe Browsing",
      status: "unavailable",
      detail: "Requires a Safe Browsing API key — not configured",
      checkedAt: at,
    },
    {
      name: "VirusTotal",
      status: "unavailable",
      detail: "Requires a VirusTotal API key — not configured",
      checkedAt: at,
    },
    {
      name: "OpenPhish",
      status: "unavailable",
      detail: "Commercial feed — public sample not queried",
      checkedAt: at,
    },
    {
      name: "PhishTank",
      status: "unavailable",
      detail: "Requires a PhishTank application key — not configured",
      checkedAt: at,
    },
  ];
}

function computeThreatLevel(score: number, reported: boolean): ThreatLevel {
  if (reported || score >= 85) return "critical";
  if (score >= 65) return "high";
  if (score >= 30) return "medium";
  return "low";
}



const XGB_LABELS: Record<string, string> = {
  url_length: "URL length",
  domain_length: "Domain length",
  num_dots: "Number of dots",
  num_hyphens: "Hyphens in host",
  num_digits: "Digits in host",
  num_special: "Special characters",
  num_subdomains: "Subdomain depth",
  https: "HTTPS enabled",
  entropy: "Hostname entropy",
  encoded_chars: "URL-encoded characters",
  suspicious_tld: "Suspicious TLD",
  has_ip: "IP address as host",
  punycode: "Punycode / IDN host",
  has_at: "@ symbol in URL",
  is_shortener: "URL shortener",
  brand_impersonation: "Brand name misuse",
  typosquat: "Typosquatting",
  sensitive_keywords: "Sensitive keywords in path",
  nonstandard_port: "Non-standard port",
  domain_age_days: "Domain age",
  threat_listed: "Threat-feed listing",
  redirect_count: "Redirect chain length",
};

const XGB_EXPLANATIONS: Record<string, string> = {
  url_length: "The model learned that unusually long URLs are typical of phishing pages that bury the real destination.",
  domain_length: "Very long registered domains are rare for legitimate brands but common for throwaway phishing domains.",
  num_dots: "Many dots mean deep subdomain nesting, which hides the real registered domain.",
  num_hyphens: "Hyphen-heavy hosts like 'secure-login-verify' are a strong learned phishing pattern.",
  num_digits: "Digit-heavy hostnames often come from auto-generated phishing infrastructure.",
  num_special: "Unusual characters in a URL are used to confuse users and evade simple filters.",
  num_subdomains: "Extra subdomain levels let attackers place a trusted brand name where the domain normally appears.",
  https: "Encrypted transport is a mild trust signal; its absence pushes the prediction toward phishing.",
  entropy: "Random-looking hostnames (high entropy) are typical of machine-generated malicious domains.",
  encoded_chars: "%XX escape sequences are used to hide keywords or payloads from filters.",
  suspicious_tld: "Free or cheap top-level domains are disproportionately used in phishing campaigns.",
  has_ip: "A raw IP instead of a domain name is one of the strongest phishing indicators the model learned.",
  punycode: "Punycode hosts imitate real brands using lookalike Unicode characters.",
  has_at: "Browsers ignore everything before '@', so attackers use it to fake the visible domain.",
  is_shortener: "Shortened links hide the true destination from both the user and static filters.",
  brand_impersonation: "A known brand appearing outside the registered domain is a classic impersonation pattern.",
  typosquat: "The domain is only one or two edits away from a real brand name.",
  sensitive_keywords: "Words like login, verify or update in the path are common on credential-harvesting pages.",
  nonstandard_port: "Legitimate login pages do not run on unusual ports.",
  domain_age_days: "Newly registered domains carry far more risk; long-established domains lower the score.",
  threat_listed: "The URL appears on a public malware/phishing feed, which dominates the prediction.",
  redirect_count: "Long redirect chains are used to launder traffic and evade blocklists.",
};

function buildFeatureVector(
  features: UrlFeatures,
  heuristics: PhishingAnalysis["heuristics"],
  metadata: DomainMetadata,
  intel: ThreatIntel,
): Record<string, number> {
  const on = (label: string) => (heuristics.find((h) => h.label === label)?.triggered ? 1 : 0);
  return {
    url_length: features.urlLength,
    domain_length: features.domainLength,
    num_dots: features.numDots,
    num_hyphens: features.numHyphens,
    num_digits: features.numDigits,
    num_special: features.numSpecialChars,
    num_subdomains: features.numSubdomains,
    https: features.httpsStatus ? 1 : 0,
    entropy: features.entropy,
    encoded_chars: features.encodedCharCount,
    suspicious_tld: features.tldType === "suspicious" ? 1 : 0,
    has_ip: on("IP address as host"),
    punycode: on("Punycode / IDN homograph"),
    has_at: on("@ symbol in URL"),
    is_shortener: on("Uses URL shortener"),
    brand_impersonation: on("Brand name in subdomain or path"),
    typosquat: on("Typosquatting suspected"),
    sensitive_keywords: on("Sensitive action words in path"),
    nonstandard_port: on("Non-standard port"),
    domain_age_days: metadata.domainAgeDays ?? 365,
    threat_listed: intel.reported ? 1 : 0,
    redirect_count: Math.max(0, metadata.redirectChain.length - 1),
  };
}

function computeFeatureImportance(prediction: XgbPrediction): FeatureContribution[] {
  const total = prediction.contributions.reduce((s, c) => s + Math.abs(c.contribution), 0) || 1;
  return prediction.contributions.slice(0, 8).map((c) => ({
    feature: XGB_LABELS[c.feature] ?? c.feature,
    contribution: Math.round((Math.abs(c.contribution) / total) * 100),
    direction: c.contribution >= 0 ? ("risk" as const) : ("safe" as const),
    explanation: XGB_EXPLANATIONS[c.feature] ?? "Contributed to the gradient-boosted model's prediction.",
  }));
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
    const startedAt = Date.now();
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
    const [metadata, threatIntel, dns] = await Promise.all([
      fetchMetadata(parsedUrl, registrable),
      fetchThreatIntel(normalizedUrl),
      fetchDns(host),
    ]);
    if (!metadata.hostingCountry && dns.hostingCountry) metadata.hostingCountry = dns.hostingCountry;


    // ---- XGBoost inference (primary classifier) ----
    const featureVector = buildFeatureVector(features, heuristics, metadata, threatIntel);
    const prediction = predict(featureVector);
    const modelScore = Math.round(prediction.probability * 100);
    const topContribs = prediction.contributions.slice(0, 8);

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

XGBoost classifier output (gradient-boosted decision trees, ${XGB_METRICS.rounds} rounds, test accuracy ${(XGB_METRICS.accuracy * 100).toFixed(1)}%):
- Phishing probability: ${(prediction.probability * 100).toFixed(1)}%
- Raw log-odds margin: ${prediction.margin.toFixed(3)}
- Top signed feature contributions (positive = pushes toward phishing):
${topContribs.map((c) => `  - ${XGB_LABELS[c.feature] ?? c.feature} = ${c.value} -> ${c.contribution >= 0 ? "+" : ""}${c.contribution}`).join("\n")}

Rule-based cross-check score: ${heuristicScore}/100

The XGBoost probability is the authoritative risk score. Keep "score" within 10 points of ${modelScore} unless the threat feed says otherwise. Explain the model's reasoning in plain language.

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

    const aiScore = Number.isFinite(parsed.score) ? Math.max(0, Math.min(100, Math.round(parsed.score))) : modelScore;
    // Blend: the XGBoost ensemble carries most of the weight, the LLM adjusts.
    let score = Math.round(modelScore * 0.7 + aiScore * 0.3);
    if (threatIntel.reported) score = Math.max(score, 90);

    const verdict: PhishingVerdict =
      parsed.verdict ?? (score >= 65 ? "dangerous" : score >= 30 ? "suspicious" : "safe");

    const aiConfidence = Number.isFinite(parsed.confidence)
      ? Math.max(0, Math.min(100, Math.round(parsed.confidence)))
      : prediction.confidence;
    const confidence = Math.max(0, Math.min(100, Math.round(prediction.confidence * 0.7 + aiConfidence * 0.3)));

    const redFlagsRaw = parsed.redFlags ?? [];
    const redFlags = Array.isArray(redFlagsRaw)
      ? redFlagsRaw.map((r: any) =>
          typeof r === "string"
            ? { label: r, explanation: "" }
            : { label: String(r.label ?? ""), explanation: String(r.explanation ?? "") },
        )
      : [];

    const featureImportance = computeFeatureImportance(prediction);
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
      model: {
        name: "PhishGuard XGBoost v1",
        algorithm: "XGBoost (gradient-boosted decision trees)",
        objective: "binary:logistic",
        rounds: XGB_METRICS.rounds,
        maxDepth: XGB_METRICS.maxDepth,
        learningRate: XGB_METRICS.learningRate,
        trainedOn: XGB_METRICS.trainedOn,
        accuracy: XGB_METRICS.accuracy,
        auc: XGB_METRICS.auc,
        probability: Math.round(prediction.probability * 1000) / 1000,
        margin: Math.round(prediction.margin * 1000) / 1000,
        topGain: Object.entries(XGB_GAIN)
          .sort((a, b) => b[1] - a[1])
          .slice(0, 6)
          .map(([feature, gain]) => ({ feature: XGB_LABELS[feature] ?? feature, gain })),
      },
      aiExplanation: parsed.aiExplanation ?? parsed.summary ?? "",
      analyzedAt: new Date().toISOString(),
      dns,
      threatServices: buildThreatServices(metadata, dns, threatIntel, features),
      scanDurationMs: Date.now() - startedAt,
      threatLevel: computeThreatLevel(score, threatIntel.reported),
    };

  });
