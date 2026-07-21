import { createFileRoute, useRouter } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { useState, type FormEvent } from "react";
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Loader2,
  Link2,
  AlertTriangle,
  CheckCircle2,
  Search,
  Sparkles,
} from "lucide-react";

import { analyzeUrl, type PhishingAnalysis } from "@/lib/phishing.functions";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "PhishGuard AI — Detect Phishing Websites in Seconds" },
      {
        name: "description",
        content:
          "Paste any URL and let AI + security heuristics flag phishing, credential theft, and brand impersonation before you click.",
      },
      { property: "og:title", content: "PhishGuard AI — Phishing Website Detection" },
      {
        property: "og:description",
        content: "AI-powered analysis of suspicious URLs, with risk scoring and clear red flags.",
      },
      { property: "og:type", content: "website" },
      { property: "og:url", content: "/" },
    ],
    links: [{ rel: "canonical", href: "/" }],
  }),
  component: Index,
});

const EXAMPLES = [
  "https://paypal.com",
  "http://paypa1-secure-login.verify-account.tk/signin",
  "https://192.168.1.10/apple-id/verify",
];

function verdictStyle(v: PhishingAnalysis["verdict"]) {
  if (v === "dangerous")
    return {
      label: "Dangerous",
      color: "text-destructive",
      bg: "bg-destructive/10",
      border: "border-destructive/40",
      Icon: ShieldX,
      ring: "ring-destructive/50",
    };
  if (v === "suspicious")
    return {
      label: "Suspicious",
      color: "text-warning",
      bg: "bg-warning/10",
      border: "border-warning/40",
      Icon: ShieldAlert,
      ring: "ring-warning/50",
    };
  return {
    label: "Likely Safe",
    color: "text-success",
    bg: "bg-success/10",
    border: "border-success/40",
    Icon: ShieldCheck,
    ring: "ring-success/50",
  };
}

function Index() {
  const router = useRouter();
  const analyze = useServerFn(analyzeUrl);
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<PhishingAnalysis | null>(null);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    if (!url.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const data = await analyze({ data: { url } });
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong.");
    } finally {
      setLoading(false);
      router.invalidate();
    }
  }

  return (
    <div className="min-h-screen bg-hero">
      <div className="min-h-screen bg-background/40 backdrop-blur-[1px]">
        <header className="mx-auto flex max-w-6xl items-center justify-between px-6 py-6">
          <div className="flex items-center gap-2.5">
            <div className="relative flex h-9 w-9 items-center justify-center rounded-xl bg-primary/15 text-primary shadow-glow">
              <Shield className="h-5 w-5" strokeWidth={2.25} />
            </div>
            <div className="leading-tight">
              <div className="text-sm font-semibold tracking-tight">PhishGuard AI</div>
              <div className="text-[11px] uppercase tracking-[0.15em] text-muted-foreground">
                Threat Intelligence
              </div>
            </div>
          </div>
          <div className="hidden items-center gap-2 rounded-full border border-border bg-card/60 px-3 py-1.5 text-xs text-muted-foreground sm:flex">
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-primary opacity-75" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-primary" />
            </span>
            Detection engine online
          </div>
        </header>

        <main className="mx-auto max-w-4xl px-6 pb-24 pt-8">
          <section className="text-center">
            <div className="inline-flex items-center gap-2 rounded-full border border-border bg-card/60 px-3 py-1 text-xs text-muted-foreground">
              <Sparkles className="h-3.5 w-3.5 text-primary" />
              AI + heuristic hybrid analysis
            </div>
            <h1 className="mt-5 text-balance text-4xl font-semibold tracking-tight sm:text-5xl md:text-6xl">
              Detect phishing websites{" "}
              <span className="bg-gradient-to-r from-primary via-primary to-accent bg-clip-text text-transparent">
                before you click
              </span>
            </h1>
            <p className="mx-auto mt-4 max-w-xl text-pretty text-base text-muted-foreground">
              Paste a suspicious link. Our engine cross-checks it against 13 phishing heuristics and
              an AI security analyst — no browsing required.
            </p>
          </section>

          <section className="mt-10">
            <form
              onSubmit={onSubmit}
              className="group relative overflow-hidden rounded-2xl border border-border bg-card/80 p-2 shadow-glow backdrop-blur-md focus-within:ring-2 focus-within:ring-ring"
            >
              <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
                <div className="flex flex-1 items-center gap-3 rounded-xl bg-background/40 px-4 py-3">
                  <Link2 className="h-5 w-5 shrink-0 text-muted-foreground" />
                  <input
                    type="text"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    placeholder="https://example.com/login"
                    autoComplete="off"
                    spellCheck={false}
                    className="w-full bg-transparent text-base text-foreground placeholder:text-muted-foreground focus:outline-none"
                  />
                </div>
                <button
                  type="submit"
                  disabled={loading || !url.trim()}
                  className="inline-flex items-center justify-center gap-2 rounded-xl bg-primary px-6 py-3 text-sm font-semibold text-primary-foreground transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {loading ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin" />
                      Scanning
                    </>
                  ) : (
                    <>
                      <Search className="h-4 w-4" />
                      Analyze URL
                    </>
                  )}
                </button>
              </div>
              {loading && (
                <div className="pointer-events-none absolute inset-x-0 bottom-0 h-px overflow-hidden">
                  <div className="h-full w-1/3 animate-scan bg-gradient-to-r from-transparent via-primary to-transparent" />
                </div>
              )}
            </form>

            <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
              <span>Try:</span>
              {EXAMPLES.map((ex) => (
                <button
                  key={ex}
                  type="button"
                  onClick={() => setUrl(ex)}
                  className="rounded-full border border-border bg-card/60 px-2.5 py-1 font-mono text-[11px] text-foreground/80 transition hover:border-primary/40 hover:text-primary"
                >
                  {ex.replace(/^https?:\/\//, "")}
                </button>
              ))}
            </div>

            {error && (
              <div className="mt-6 flex items-start gap-3 rounded-xl border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive animate-fade-up">
                <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0" />
                <div>{error}</div>
              </div>
            )}
          </section>

          {result && <ResultView result={result} />}

          {!result && !error && !loading && (
            <section className="mt-16 grid gap-4 sm:grid-cols-3">
              {[
                {
                  Icon: Search,
                  title: "13 heuristic checks",
                  body: "IP hosts, punycode, brand-in-subdomain, shorteners, suspicious TLDs and more.",
                },
                {
                  Icon: Sparkles,
                  title: "AI reasoning",
                  body: "A security-tuned model reviews the signals and writes a plain-English verdict.",
                },
                {
                  Icon: ShieldCheck,
                  title: "No browsing needed",
                  body: "We never visit the URL — all analysis is done on the URL structure itself.",
                },
              ].map(({ Icon, title, body }) => (
                <div
                  key={title}
                  className="rounded-2xl border border-border bg-card/60 p-5 backdrop-blur"
                >
                  <Icon className="h-5 w-5 text-primary" />
                  <div className="mt-3 text-sm font-semibold">{title}</div>
                  <div className="mt-1 text-sm text-muted-foreground">{body}</div>
                </div>
              ))}
            </section>
          )}
        </main>
      </div>
    </div>
  );
}

function ResultView({ result }: { result: PhishingAnalysis }) {
  const s = verdictStyle(result.verdict);
  const { Icon } = s;
  const triggered = result.heuristics.filter((h) => h.triggered);

  return (
    <section className="mt-10 space-y-5 animate-fade-up">
      <div
        className={`overflow-hidden rounded-2xl border ${s.border} ${s.bg} backdrop-blur-md`}
      >
        <div className="flex flex-col gap-6 p-6 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-start gap-4">
            <div
              className={`flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl bg-background/40 ring-2 ${s.ring} ${s.color}`}
            >
              <Icon className="h-7 w-7" strokeWidth={2.2} />
            </div>
            <div className="min-w-0">
              <div className={`text-xs font-semibold uppercase tracking-[0.18em] ${s.color}`}>
                {s.label}
              </div>
              <div className="mt-1 truncate font-mono text-sm text-foreground/90">
                {result.normalizedUrl}
              </div>
              <p className="mt-2 max-w-xl text-sm text-foreground/80">{result.summary}</p>
            </div>
          </div>
          <ScoreDial score={result.score} color={s.color} />
        </div>
        <div className="border-t border-border/60 bg-background/30 px-6 py-4 text-sm">
          <span className="font-semibold text-foreground">Recommendation: </span>
          <span className="text-muted-foreground">{result.recommendation}</span>
        </div>
      </div>

      <div className="grid gap-5 md:grid-cols-2">
        <FlagList
          title="Red flags"
          items={result.redFlags}
          empty="No significant red flags detected."
          tone="danger"
        />
        <FlagList
          title="Reassuring signals"
          items={result.greenFlags}
          empty="No strongly reassuring signals detected."
          tone="success"
        />
      </div>

      <div className="rounded-2xl border border-border bg-card/60 p-5 backdrop-blur">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold">Heuristic breakdown</h3>
          <span className="text-xs text-muted-foreground">
            {triggered.length}/{result.heuristics.length} triggered
          </span>
        </div>
        <ul className="mt-4 grid gap-2 sm:grid-cols-2">
          {result.heuristics.map((h) => (
            <li
              key={h.label}
              className={`flex items-start gap-3 rounded-lg border px-3 py-2.5 text-sm transition ${
                h.triggered
                  ? h.weight === "high"
                    ? "border-destructive/40 bg-destructive/5"
                    : h.weight === "medium"
                      ? "border-warning/40 bg-warning/5"
                      : "border-border bg-muted/40"
                  : "border-border/50 bg-background/30 opacity-60"
              }`}
            >
              <span
                className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${
                  h.triggered
                    ? h.weight === "high"
                      ? "bg-destructive"
                      : h.weight === "medium"
                        ? "bg-warning"
                        : "bg-muted-foreground"
                    : "bg-border"
                }`}
              />
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className="font-medium text-foreground">{h.label}</span>
                  <span className="rounded border border-border px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-muted-foreground">
                    {h.weight}
                  </span>
                </div>
                <div className="mt-0.5 text-xs text-muted-foreground">{h.detail}</div>
              </div>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}

function ScoreDial({ score, color }: { score: number; color: string }) {
  const radius = 44;
  const c = 2 * Math.PI * radius;
  const offset = c - (score / 100) * c;
  return (
    <div className="relative flex h-28 w-28 shrink-0 items-center justify-center self-center sm:self-auto">
      <svg viewBox="0 0 100 100" className="h-28 w-28 -rotate-90">
        <circle cx="50" cy="50" r={radius} strokeWidth="8" className="fill-none stroke-border" />
        <circle
          cx="50"
          cy="50"
          r={radius}
          strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray={c}
          strokeDashoffset={offset}
          className={`fill-none ${color} transition-all duration-700`}
          stroke="currentColor"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <div className={`text-2xl font-semibold ${color}`}>{score}</div>
        <div className="text-[10px] uppercase tracking-wider text-muted-foreground">risk</div>
      </div>
    </div>
  );
}

function FlagList({
  title,
  items,
  empty,
  tone,
}: {
  title: string;
  items: string[];
  empty: string;
  tone: "danger" | "success";
}) {
  const Icon = tone === "danger" ? AlertTriangle : CheckCircle2;
  const color = tone === "danger" ? "text-destructive" : "text-success";
  return (
    <div className="rounded-2xl border border-border bg-card/60 p-5 backdrop-blur">
      <div className="flex items-center gap-2">
        <Icon className={`h-4 w-4 ${color}`} />
        <h3 className="text-sm font-semibold">{title}</h3>
      </div>
      {items.length === 0 ? (
        <p className="mt-3 text-sm text-muted-foreground">{empty}</p>
      ) : (
        <ul className="mt-3 space-y-2">
          {items.map((it, i) => (
            <li key={i} className="flex gap-2 text-sm text-foreground/85">
              <span className={`mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full ${tone === "danger" ? "bg-destructive" : "bg-success"}`} />
              <span>{it}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
