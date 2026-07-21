import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";

const InputSchema = z.object({
  url: z.string().trim().min(1),
});

export type PhishingVerdict = "safe" | "suspicious" | "dangerous";

export interface PhishingAnalysis {
  url: string;
  normalizedUrl: string;
  score: number; // 0-100, higher = more likely phishing
  verdict: PhishingVerdict;
  summary: string;
  redFlags: string[];
  greenFlags: string[];
  recommendation: string;
  heuristics: {
    label: string;
    detail: string;
    weight: "low" | "medium" | "high";
    triggered: boolean;
  }[];
}

function normalize(raw: string): string {
  let u = raw.trim();
  if (!/^https?:\/\//i.test(u)) u = "https://" + u;
  return u;
}

function runHeuristics(rawUrl: string) {
  const url = new URL(rawUrl);
  const host = url.hostname.toLowerCase();
  const path = url.pathname + url.search;
  const full = url.href;

  const brandKeywords = [
    "paypal", "apple", "microsoft", "google", "amazon", "facebook",
    "instagram", "netflix", "bank", "wellsfargo", "chase", "amex",
    "coinbase", "binance", "metamask", "outlook", "office365", "dhl",
    "fedex", "usps", "irs", "gov", "login", "verify", "secure", "update",
  ];
  const suspiciousTlds = [".zip", ".mov", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".click", ".country", ".work"];
  const shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly"];

  const parts = host.split(".");
  const tld = "." + parts[parts.length - 1];
  const registrable = parts.slice(-2).join(".");

  const hasIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
  const isPunycode = host.includes("xn--");
  const hyphenCount = (host.match(/-/g) || []).length;
  const subdomainDepth = Math.max(0, parts.length - 2);
  const isHttps = url.protocol === "https:";
  const hasPort = !!url.port && url.port !== "80" && url.port !== "443";
  const hasAtSymbol = full.includes("@");
  const hasCredsInPath = /(login|verify|update|secure|account|wallet|signin|confirm)/i.test(path);
  const brandInSubdomainOrPath = brandKeywords.some(
    (b) => (parts.slice(0, -2).join(".").includes(b) || path.toLowerCase().includes(b)) && !registrable.includes(b),
  );
  const suspiciousTld = suspiciousTlds.includes(tld);
  const isShortener = shorteners.includes(registrable);
  const longUrl = full.length > 100;
  const manyDigits = (host.match(/\d/g) || []).length >= 4;

  const heuristics: PhishingAnalysis["heuristics"] = [
    { label: "IP address as host", detail: `Host is ${host}`, weight: "high", triggered: hasIp },
    { label: "Punycode / IDN homograph", detail: "Hostname contains xn-- (unicode disguise)", weight: "high", triggered: isPunycode },
    { label: "No HTTPS", detail: `Protocol is ${url.protocol}`, weight: "medium", triggered: !isHttps },
    { label: "Uses URL shortener", detail: `${registrable} hides the true destination`, weight: "medium", triggered: isShortener },
    { label: "Suspicious TLD", detail: `${tld} is commonly abused`, weight: "medium", triggered: suspiciousTld },
    { label: "Brand name in subdomain or path", detail: "Impersonation pattern (e.g. paypal.login.example.com)", weight: "high", triggered: brandInSubdomainOrPath },
    { label: "Deep subdomain nesting", detail: `${subdomainDepth} subdomain levels`, weight: "low", triggered: subdomainDepth >= 3 },
    { label: "Excessive hyphens in host", detail: `${hyphenCount} hyphens`, weight: "low", triggered: hyphenCount >= 3 },
    { label: "@ symbol in URL", detail: "Can mask the real host", weight: "high", triggered: hasAtSymbol },
    { label: "Sensitive action words in path", detail: "login/verify/secure/update present", weight: "low", triggered: hasCredsInPath },
    { label: "Non-standard port", detail: `Port ${url.port}`, weight: "medium", triggered: hasPort },
    { label: "Very long URL", detail: `${full.length} characters`, weight: "low", triggered: longUrl },
    { label: "Digit-heavy hostname", detail: "Many numeric characters in host", weight: "low", triggered: manyDigits },
  ];

  const weightMap = { low: 6, medium: 14, high: 22 } as const;
  let score = 0;
  for (const h of heuristics) if (h.triggered) score += weightMap[h.weight];
  score = Math.min(100, score);

  return { heuristics, score, host, registrable };
}

export const analyzeUrl = createServerFn({ method: "POST" })
  .inputValidator((data: unknown) => InputSchema.parse(data))
  .handler(async ({ data }): Promise<PhishingAnalysis> => {
    const apiKey = process.env.LOVABLE_API_KEY;
    if (!apiKey) throw new Error("Missing LOVABLE_API_KEY");

    let normalizedUrl: string;
    try {
      normalizedUrl = normalize(data.url);
      new URL(normalizedUrl);
    } catch {
      throw new Error("That doesn't look like a valid URL.");
    }

    const { heuristics, score: heuristicScore, host, registrable } = runHeuristics(normalizedUrl);
    const triggered = heuristics.filter((h) => h.triggered);

    const systemPrompt = `You are a cybersecurity analyst specializing in phishing detection. You analyze URLs for signs of phishing, credential theft, brand impersonation, and scams. You NEVER visit URLs — you reason from the URL string, the domain structure, and the heuristic signals provided. Be concise, factual, and cautious. If unsure, say so.`;

    const userPrompt = `Analyze this URL for phishing risk.

URL: ${normalizedUrl}
Host: ${host}
Registrable domain: ${registrable}

Heuristic signals already computed (${triggered.length} triggered / ${heuristics.length} total):
${heuristics.map((h) => `- [${h.triggered ? "X" : " "}] (${h.weight}) ${h.label}: ${h.detail}`).join("\n")}

Preliminary heuristic score: ${heuristicScore}/100 (higher = more likely phishing)

Return a JSON object with:
- "score": integer 0-100 (your final risk score, informed by but not equal to the heuristic score)
- "verdict": one of "safe" | "suspicious" | "dangerous"
- "summary": 1-2 sentence plain-English verdict
- "redFlags": array of 2-6 concrete concerns (strings)
- "greenFlags": array of 0-4 reassuring signals (strings)
- "recommendation": 1 sentence action the user should take

Return ONLY the JSON, no markdown, no code fences.`;

    const response = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Lovable-API-Key": apiKey,
      },
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

    let parsed: {
      score?: number;
      verdict?: PhishingVerdict;
      summary?: string;
      redFlags?: string[];
      greenFlags?: string[];
      recommendation?: string;
    };
    try {
      parsed = JSON.parse(content);
    } catch {
      const match = content.match(/\{[\s\S]*\}/);
      parsed = match ? JSON.parse(match[0]) : {};
    }

    const score = Math.max(0, Math.min(100, Math.round(parsed.score ?? heuristicScore)));
    const verdict: PhishingVerdict =
      parsed.verdict ?? (score >= 65 ? "dangerous" : score >= 30 ? "suspicious" : "safe");

    return {
      url: data.url,
      normalizedUrl,
      score,
      verdict,
      summary: parsed.summary ?? "No summary available.",
      redFlags: parsed.redFlags ?? triggered.filter((h) => h.weight !== "low").map((h) => h.label),
      greenFlags: parsed.greenFlags ?? [],
      recommendation:
        parsed.recommendation ??
        (verdict === "safe"
          ? "This URL looks fine, but always double-check before entering credentials."
          : "Do not enter any personal information or credentials on this site."),
      heuristics,
    };
  });
