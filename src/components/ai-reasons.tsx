import type { PhishingAnalysis } from "@/lib/phishing.functions";
import {
  Brain, KeyRound, Ruler, Copy, CalendarPlus, LockOpen, Repeat, Shuffle, Link2,
  Fingerprint, Network, CheckCircle2,
} from "lucide-react";

type Reason = {
  key: string;
  title: string;
  icon: React.ReactNode;
  triggered: boolean;
  detail: string;
  explanation: string;
};

function heur(result: PhishingAnalysis, label: string) {
  return result.heuristics.find((h) => h.label === label);
}

export function buildReasons(result: PhishingAnalysis): Reason[] {
  const f = result.features;
  const m = result.metadata;
  const pick = (label: string, fallbackDetail: string, fallbackExp: string) => {
    const h = heur(result, label);
    return {
      triggered: !!h?.triggered,
      detail: h?.detail ?? fallbackDetail,
      explanation: h?.explanation ?? fallbackExp,
    };
  };

  const keywords = pick("Sensitive action words in path", "No sensitive keywords", "Words like login, verify or update are common on credential-harvesting pages.");
  const brand = pick("Brand name in subdomain or path", "No brand impersonation detected", "A known brand outside the registered domain is a classic impersonation pattern.");
  const https = pick("No HTTPS", `Protocol check`, "Plain HTTP is unencrypted — real login pages always use HTTPS.");
  const entropy = pick("High-entropy hostname", `Entropy ${f.entropy}`, "Random-looking hostnames are typical of auto-generated phishing infrastructure.");
  const shortener = pick("Uses URL shortener", "No shortener used", "Shorteners hide the real destination from users and filters.");
  const typo = pick("Typosquatting suspected", "No lookalike brand domain found", "The domain is one or two edits away from a real brand name.");
  const ip = pick("IP address as host", "Host is a domain name", "A raw IP instead of a domain is a strong phishing indicator.");
  const redirects = Math.max(0, (m.redirectChain?.length ?? 1) - 1);
  const age = m.domainAgeDays;

  return [
    { key: "keywords", title: "Suspicious keywords", icon: <KeyRound className="h-4 w-4" />, ...keywords },
    {
      key: "long", title: "Long URL", icon: <Ruler className="h-4 w-4" />,
      triggered: f.urlLength > 100,
      detail: `${f.urlLength} characters`,
      explanation: "Very long URLs bury the real destination past the visible part of the address bar.",
    },
    { key: "brand", title: "Brand impersonation", icon: <Copy className="h-4 w-4" />, ...brand },
    {
      key: "age", title: "Newly registered domain", icon: <CalendarPlus className="h-4 w-4" />,
      triggered: age !== null && age !== undefined && age < 180,
      detail: age !== null && age !== undefined ? `${age} days old` : "Registration date unknown",
      explanation: "Phishing domains are usually days or weeks old; established brands are years old.",
    },
    { key: "https", title: "Missing HTTPS", icon: <LockOpen className="h-4 w-4" />, ...https, triggered: !f.httpsStatus },
    {
      key: "redirects", title: "Too many redirects", icon: <Repeat className="h-4 w-4" />,
      triggered: redirects >= 2,
      detail: redirects > 0 ? `${redirects} redirect hop${redirects > 1 ? "s" : ""}` : "No redirects observed",
      explanation: "Long redirect chains launder traffic and evade blocklists.",
    },
    { key: "entropy", title: "High URL entropy", icon: <Shuffle className="h-4 w-4" />, ...entropy },
    { key: "shortener", title: "URL shortener", icon: <Link2 className="h-4 w-4" />, ...shortener },
    { key: "typo", title: "Typosquatting detected", icon: <Fingerprint className="h-4 w-4" />, ...typo },
    { key: "ip", title: "IP address instead of domain", icon: <Network className="h-4 w-4" />, ...ip },
  ];
}

export function AiReasonCards({ result }: { result: PhishingAnalysis }) {
  const reasons = buildReasons(result);
  const hits = reasons.filter((r) => r.triggered).length;

  return (
    <div className="rounded-2xl border border-border bg-card/60 p-5 backdrop-blur">
      <div className="mb-1 flex items-center gap-2">
        <Brain className="h-4 w-4 text-primary" />
        <h3 className="text-sm font-semibold">AI explanation — why this verdict?</h3>
        <span className="ml-auto text-xs text-muted-foreground">{hits}/{reasons.length} signals fired</span>
      </div>
      <p className="mb-4 text-sm text-foreground/80">{result.aiExplanation || result.summary}</p>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {reasons.map((r) => (
          <div
            key={r.key}
            className={`rounded-xl border p-3.5 transition ${
              r.triggered
                ? "border-destructive/40 bg-destructive/5 hover:border-destructive/60"
                : "border-border/60 bg-background/30 opacity-80 hover:opacity-100"
            }`}
          >
            <div className="flex items-center gap-2">
              <span className={r.triggered ? "text-destructive" : "text-success"}>
                {r.triggered ? r.icon : <CheckCircle2 className="h-4 w-4" />}
              </span>
              <span className="text-sm font-medium text-foreground">{r.title}</span>
              <span
                className={`ml-auto rounded-full border px-1.5 py-0.5 text-[10px] uppercase tracking-wide ${
                  r.triggered ? "border-destructive/40 text-destructive" : "border-success/40 text-success"
                }`}
              >
                {r.triggered ? "Detected" : "Clear"}
              </span>
            </div>
            <div className="mt-1.5 text-[11px] text-muted-foreground">{r.detail}</div>
            <p className="mt-1.5 text-[11px] leading-relaxed text-foreground/70">{r.explanation}</p>
          </div>
        ))}
      </div>
    </div>
  );
}
