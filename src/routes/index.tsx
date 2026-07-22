import type { HistoryEntry as HE } from "@/lib/history";
import { useEffect, useMemo, useState, type FormEvent } from "react";
import { createFileRoute, useRouter, Link } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import {
  Shield, ShieldAlert, ShieldCheck, ShieldX, Loader2, Link2, AlertTriangle,
  CheckCircle2, Search, Sparkles, FileJson, FileText, FileDown, Star, StarOff,
  Trash2, Sun, Moon, History, BarChart3, Info, Globe, Lock, LockOpen, Radar,
  ClipboardList, Brain, ArrowRight, ExternalLink, LogIn, LogOut, User as UserIcon,
} from "lucide-react";

import { analyzeUrl, type PhishingAnalysis as PA } from "@/lib/phishing.functions";
import { addToHistory, clearHistory, deleteEntry, getHistory, toggleFavorite } from "@/lib/history";
import { exportCSV, exportJSON, exportPDF } from "@/lib/report";
import { applyTheme, getTheme, toggleTheme, type Theme } from "@/lib/theme";
import { useAuth } from "@/hooks/use-auth";
import { listScans, saveScan, deleteScan, setScanFavorite, clearScans } from "@/lib/scans.functions";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "PhishGuard AI — Advanced Phishing URL Detection" },
      {
        name: "description",
        content:
          "Paste any URL and get an AI-powered phishing risk analysis with WHOIS metadata, threat-intel lookup, feature breakdown, and downloadable reports.",
      },
      { property: "og:title", content: "PhishGuard AI — Advanced Phishing URL Detection" },
      {
        property: "og:description",
        content:
          "Hybrid AI + heuristic phishing detection with domain metadata, threat feeds, explainable scoring, and PDF/JSON/CSV reports.",
      },
      { property: "og:type", content: "website" },
      { property: "og:url", content: "/" },
    ],
    links: [{ rel: "canonical", href: "/" }],
  }),
  component: Index,
});

type Tab = "scan" | "history" | "analytics";

const EXAMPLES = [
  "https://paypal.com",
  "http://paypa1-secure-login.verify-account.tk/signin",
  "https://192.168.1.10/apple-id/verify",
];

function verdictStyle(v: PA["verdict"]) {
  if (v === "dangerous")
    return { label: "Dangerous", color: "text-destructive", bg: "bg-destructive/10", border: "border-destructive/40", Icon: ShieldX, ring: "ring-destructive/50", solid: "bg-destructive" };
  if (v === "suspicious")
    return { label: "Suspicious", color: "text-warning", bg: "bg-warning/10", border: "border-warning/40", Icon: ShieldAlert, ring: "ring-warning/50", solid: "bg-warning" };
  return { label: "Likely Safe", color: "text-success", bg: "bg-success/10", border: "border-success/40", Icon: ShieldCheck, ring: "ring-success/50", solid: "bg-success" };
}

function Index() {
  const router = useRouter();
  const analyze = useServerFn(analyzeUrl);
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<PA | null>(null);
  const [tab, setTab] = useState<Tab>("scan");
  const [theme, setTheme] = useState<Theme>("dark");
  const [history, setHistory] = useState<HE[]>([]);

  useEffect(() => {
    const t = getTheme();
    applyTheme(t);
    setTheme(t);
    setHistory(getHistory());
    const onChange = () => setHistory(getHistory());
    window.addEventListener("phishguard:history-changed", onChange);
    return () => window.removeEventListener("phishguard:history-changed", onChange);
  }, []);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    if (!url.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const data = await analyze({ data: { url } });
      setResult(data);
      addToHistory(data);
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
              <div className="text-[11px] uppercase tracking-[0.15em] text-muted-foreground">Threat Intelligence</div>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <nav className="flex items-center gap-1 rounded-full border border-border bg-card/60 p-1 text-xs">
              <TabBtn active={tab === "scan"} onClick={() => setTab("scan")} icon={<Search className="h-3.5 w-3.5" />}>Scan</TabBtn>
              <TabBtn active={tab === "history"} onClick={() => setTab("history")} icon={<History className="h-3.5 w-3.5" />}>History</TabBtn>
              <TabBtn active={tab === "analytics"} onClick={() => setTab("analytics")} icon={<BarChart3 className="h-3.5 w-3.5" />}>Analytics</TabBtn>
            </nav>
            <button
              onClick={() => setTheme(toggleTheme())}
              className="inline-flex h-9 w-9 items-center justify-center rounded-full border border-border bg-card/60 text-muted-foreground hover:text-foreground"
              aria-label="Toggle theme"
              title="Toggle theme"
            >
              {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
            </button>
          </div>
        </header>

        <main className="mx-auto max-w-5xl px-6 pb-24 pt-4">
          {tab === "scan" && (
            <ScanTab
              url={url} setUrl={setUrl} loading={loading} error={error} result={result} onSubmit={onSubmit}
            />
          )}
          {tab === "history" && <HistoryTab history={history} onOpen={(a) => { setResult(a); setTab("scan"); }} />}
          {tab === "analytics" && <AnalyticsTab history={history} />}
        </main>
      </div>
    </div>
  );
}

function TabBtn({ active, onClick, children, icon }: { active: boolean; onClick: () => void; children: React.ReactNode; icon: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1.5 transition ${active ? "bg-primary text-primary-foreground shadow-glow" : "text-muted-foreground hover:text-foreground"}`}
    >
      {icon}{children}
    </button>
  );
}

function ScanTab({
  url, setUrl, loading, error, result, onSubmit,
}: {
  url: string; setUrl: (s: string) => void; loading: boolean; error: string | null;
  result: PA | null; onSubmit: (e: FormEvent) => void;
}) {
  return (
    <>
      <section className="text-center">
        <div className="inline-flex items-center gap-2 rounded-full border border-border bg-card/60 px-3 py-1 text-xs text-muted-foreground">
          <Sparkles className="h-3.5 w-3.5 text-primary" />
          AI + heuristics + threat intel
        </div>
        <h1 className="mt-5 text-balance text-4xl font-semibold tracking-tight sm:text-5xl md:text-6xl">
          Detect phishing websites{" "}
          <span className="bg-gradient-to-r from-primary via-primary to-accent bg-clip-text text-transparent">before you click</span>
        </h1>
        <p className="mx-auto mt-4 max-w-xl text-pretty text-base text-muted-foreground">
          Paste a suspicious link. We cross-check it against 16 heuristics, WHOIS/RDAP metadata, live threat feeds, and an AI security analyst.
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
              {loading ? (<><Loader2 className="h-4 w-4 animate-spin" />Scanning</>) : (<><Search className="h-4 w-4" />Analyze URL</>)}
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

        {loading && <LoadingStages />}

        {error && (
          <div className="mt-6 flex items-start gap-3 rounded-xl border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive animate-fade-up">
            <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0" />
            <div>{error}</div>
          </div>
        )}
      </section>

      {result && <ResultView result={result} />}
    </>
  );
}

function LoadingStages() {
  const stages = ["Parsing URL", "Running 16 heuristics", "Fetching RDAP/WHOIS", "Checking threat feeds", "Consulting AI analyst"];
  return (
    <div className="mt-6 rounded-xl border border-border bg-card/60 p-4 text-sm animate-fade-up">
      <div className="mb-3 flex items-center gap-2 text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin text-primary" />
        Running deep scan…
      </div>
      <ul className="grid gap-1.5 sm:grid-cols-2">
        {stages.map((s, i) => (
          <li key={s} className="flex items-center gap-2 text-xs text-muted-foreground">
            <span className="h-1.5 w-1.5 rounded-full bg-primary" style={{ opacity: 0.4 + i * 0.12 }} />
            {s}
          </li>
        ))}
      </ul>
    </div>
  );
}

function ResultView({ result }: { result: PA }) {
  const s = verdictStyle(result.verdict);
  const { Icon } = s;
  const triggered = result.heuristics.filter((h) => h.triggered);

  return (
    <section className="mt-10 space-y-5 animate-fade-up">
      {/* Header card */}
      <div className={`overflow-hidden rounded-2xl border ${s.border} ${s.bg} backdrop-blur-md`}>
        <div className="flex flex-col gap-6 p-6 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-start gap-4">
            <div className={`flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl bg-background/40 ring-2 ${s.ring} ${s.color}`}>
              <Icon className="h-7 w-7" strokeWidth={2.2} />
            </div>
            <div className="min-w-0">
              <div className={`text-xs font-semibold uppercase tracking-[0.18em] ${s.color}`}>{s.label}</div>
              <div className="mt-1 truncate font-mono text-sm text-foreground/90">{result.normalizedUrl}</div>
              <p className="mt-2 max-w-xl text-sm text-foreground/80">{result.summary}</p>
              <div className="mt-3 flex flex-wrap gap-2 text-xs">
                <Badge tone={result.verdict === "safe" ? "success" : result.verdict === "suspicious" ? "warning" : "danger"}>
                  {s.label}
                </Badge>
                <Badge tone="neutral"><Radar className="mr-1 h-3 w-3" />Confidence {result.confidence}%</Badge>
                {result.threatIntel.reported && <Badge tone="danger"><AlertTriangle className="mr-1 h-3 w-3" />On threat feed</Badge>}
                {result.features.httpsStatus
                  ? <Badge tone="success"><Lock className="mr-1 h-3 w-3" />HTTPS</Badge>
                  : <Badge tone="danger"><LockOpen className="mr-1 h-3 w-3" />No HTTPS</Badge>}
              </div>
            </div>
          </div>
          <div className="flex flex-col items-center gap-3">
            <ScoreDial score={result.score} color={s.color} />
            <ConfidenceMeter value={result.confidence} />
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2 border-t border-border/60 bg-background/30 px-6 py-3">
          <span className="text-xs uppercase tracking-wider text-muted-foreground">Export report:</span>
          <ReportBtn onClick={() => exportPDF(result)} icon={<FileDown className="h-3.5 w-3.5" />}>PDF</ReportBtn>
          <ReportBtn onClick={() => exportJSON(result)} icon={<FileJson className="h-3.5 w-3.5" />}>JSON</ReportBtn>
          <ReportBtn onClick={() => exportCSV(result)} icon={<FileText className="h-3.5 w-3.5" />}>CSV</ReportBtn>
        </div>
      </div>

      {/* Threat intel + metadata */}
      <div className="grid gap-5 md:grid-cols-2">
        <ThreatIntelPanel result={result} />
        <MetadataPanel result={result} />
      </div>

      {/* Red flags & green flags */}
      <div className="grid gap-5 md:grid-cols-2">
        <FlagList title="Red flags (explained)" items={result.redFlags} empty="No significant red flags detected." tone="danger" />
        <SimpleList title="Reassuring signals" items={result.greenFlags} empty="No strongly reassuring signals detected." tone="success" />
      </div>

      {/* Explainable AI */}
      <ExplainablePanel result={result} />

      {/* Security indicators */}
      <SecurityIndicators heuristics={result.heuristics} triggeredCount={triggered.length} />

      {/* Feature breakdown */}
      <FeatureBreakdown result={result} />

      {/* Recommendations */}
      <RecommendationsPanel result={result} />

      {/* Preview notice */}
      <div className="rounded-2xl border border-border bg-card/60 p-5 text-sm text-muted-foreground backdrop-blur">
        <div className="flex items-start gap-2">
          <Info className="mt-0.5 h-4 w-4 shrink-0 text-primary" />
          <div>
            <div className="font-semibold text-foreground">Website preview unavailable for safety</div>
            <p className="mt-1">
              We intentionally never load or render potentially malicious pages. All analysis is done on the URL structure, DNS/WHOIS metadata, and public threat feeds.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}

function Badge({ tone, children }: { tone: "success" | "warning" | "danger" | "neutral"; children: React.ReactNode }) {
  const map = {
    success: "border-success/40 bg-success/10 text-success",
    warning: "border-warning/40 bg-warning/10 text-warning",
    danger: "border-destructive/40 bg-destructive/10 text-destructive",
    neutral: "border-border bg-background/40 text-muted-foreground",
  } as const;
  return <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] ${map[tone]}`}>{children}</span>;
}

function ReportBtn({ onClick, icon, children }: { onClick: () => void; icon: React.ReactNode; children: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      className="inline-flex items-center gap-1.5 rounded-full border border-border bg-card/60 px-3 py-1 text-xs text-foreground/85 transition hover:border-primary/40 hover:text-primary"
    >
      {icon}{children}
    </button>
  );
}

function ScoreDial({ score, color }: { score: number; color: string }) {
  const radius = 44;
  const c = 2 * Math.PI * radius;
  const offset = c - (score / 100) * c;
  return (
    <div className="relative flex h-28 w-28 shrink-0 items-center justify-center">
      <svg viewBox="0 0 100 100" className="h-28 w-28 -rotate-90">
        <circle cx="50" cy="50" r={radius} strokeWidth="8" className="fill-none stroke-border" />
        <circle
          cx="50" cy="50" r={radius}
          strokeWidth="8" strokeLinecap="round"
          strokeDasharray={c} strokeDashoffset={offset}
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

function ConfidenceMeter({ value }: { value: number }) {
  return (
    <div className="w-28">
      <div className="mb-1 flex items-center justify-between text-[10px] uppercase tracking-wider text-muted-foreground">
        <span>Confidence</span><span>{value}%</span>
      </div>
      <div className="h-1.5 overflow-hidden rounded-full bg-border">
        <div className="h-full bg-primary transition-all duration-700" style={{ width: `${value}%` }} />
      </div>
    </div>
  );
}

function ThreatIntelPanel({ result }: { result: PA }) {
  const ti = result.threatIntel;
  return (
    <div className="rounded-2xl border border-border bg-card/60 p-5 backdrop-blur">
      <div className="mb-3 flex items-center gap-2">
        <Radar className="h-4 w-4 text-primary" />
        <h3 className="text-sm font-semibold">Threat intelligence</h3>
      </div>
      <div className="grid gap-2 text-sm">
        <Row k="Source" v={ti.source} />
        <Row k="Status" v={
          <span className={ti.reported ? "text-destructive font-medium" : "text-success font-medium"}>
            {ti.reported ? "Reported / active" : ti.checked ? "Not on public feed" : "Not checked"}
          </span>
        } />
        {ti.threat && <Row k="Threat type" v={ti.threat} />}
        {ti.firstSeen && <Row k="First seen" v={ti.firstSeen} />}
        {ti.lastSeen && <Row k="Last seen" v={ti.lastSeen} />}
        {ti.reference && (
          <Row k="Reference" v={
            <a href={ti.reference} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1 text-primary hover:underline">
              View report <ExternalLink className="h-3 w-3" />
            </a>
          } />
        )}
        {ti.error && <div className="text-xs text-muted-foreground">Lookup error: {ti.error}</div>}
      </div>
    </div>
  );
}

function MetadataPanel({ result }: { result: PA }) {
  const m = result.metadata;
  return (
    <div className="rounded-2xl border border-border bg-card/60 p-5 backdrop-blur">
      <div className="mb-3 flex items-center gap-2">
        <Globe className="h-4 w-4 text-primary" />
        <h3 className="text-sm font-semibold">Domain & SSL metadata</h3>
      </div>
      <div className="grid gap-2 text-sm">
        <Row k="Registrable domain" v={<span className="font-mono">{m.registrableDomain}</span>} />
        <Row k="Registrar" v={m.registrar ?? "—"} />
        <Row k="Registered" v={fmtDate(m.registrationDate)} />
        <Row k="Expires" v={fmtDate(m.expirationDate)} />
        <Row k="Domain age" v={m.domainAgeDays !== null ? `${m.domainAgeDays} days` : "—"} />
        <Row k="Days until expiry" v={m.daysUntilExpiry !== null ? `${m.daysUntilExpiry} days` : "—"} />
        <Row k="HTTPS reachable" v={m.ssl.httpsReachable ? "Yes" : "No"} />
        <Row k="HTTP status" v={m.ssl.status ?? "—"} />
        <Row k="Hosting country" v={m.hostingCountry ?? "unknown"} />
        {m.nameservers.length > 0 && (
          <Row k="Nameservers" v={<span className="font-mono text-xs">{m.nameservers.slice(0, 3).join(", ")}</span>} />
        )}
        {m.redirectChain.length > 0 && (
          <div className="mt-1">
            <div className="mb-1 text-xs uppercase tracking-wider text-muted-foreground">Redirect chain</div>
            <ol className="space-y-1 text-xs font-mono">
              {m.redirectChain.map((c, i) => (
                <li key={i} className="flex items-start gap-2">
                  <ArrowRight className="mt-0.5 h-3 w-3 shrink-0 text-primary" />
                  <span className="break-all">{c}</span>
                </li>
              ))}
            </ol>
          </div>
        )}
      </div>
    </div>
  );
}

function Row({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-border/40 pb-1.5 last:border-0">
      <span className="text-xs uppercase tracking-wider text-muted-foreground">{k}</span>
      <span className="text-right text-foreground/90 max-w-[65%] break-words">{v}</span>
    </div>
  );
}

function fmtDate(iso: string | null): string {
  if (!iso) return "—";
  try { return new Date(iso).toLocaleDateString(); } catch { return iso; }
}

function FlagList({
  title, items, empty, tone,
}: { title: string; items: { label: string; explanation: string }[]; empty: string; tone: "danger" | "success" }) {
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
        <ul className="mt-3 space-y-3">
          {items.map((it, i) => (
            <li key={i} className="flex gap-2 text-sm text-foreground/90">
              <span className={`mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full ${tone === "danger" ? "bg-destructive" : "bg-success"}`} />
              <div>
                <div className="font-medium">{it.label}</div>
                {it.explanation && <div className="text-xs text-muted-foreground">{it.explanation}</div>}
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function SimpleList({
  title, items, empty, tone,
}: { title: string; items: string[]; empty: string; tone: "danger" | "success" }) {
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

function ExplainablePanel({ result }: { result: PA }) {
  const max = Math.max(1, ...result.featureImportance.map((f) => f.contribution));
  return (
    <div className="rounded-2xl border border-border bg-card/60 p-5 backdrop-blur">
      <div className="mb-3 flex items-center gap-2">
        <Brain className="h-4 w-4 text-primary" />
        <h3 className="text-sm font-semibold">Explainable AI</h3>
      </div>
      <p className="text-sm text-foreground/85">{result.aiExplanation}</p>
      <div className="mt-2 text-xs text-muted-foreground">
        Confidence: <span className="text-foreground">{result.confidence}%</span> · Risk score: <span className="text-foreground">{result.score}/100</span>
      </div>
      <div className="mt-4">
        <div className="mb-2 text-xs uppercase tracking-wider text-muted-foreground">Feature importance</div>
        <ul className="space-y-2">
          {result.featureImportance.map((f) => (
            <li key={f.feature} className="text-xs">
              <div className="flex items-center justify-between">
                <span className="text-foreground/90">{f.feature}</span>
                <span className={f.direction === "risk" ? "text-destructive" : "text-success"}>
                  {f.direction === "risk" ? "+" : "-"}{f.contribution}
                </span>
              </div>
              <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-border">
                <div
                  className={`h-full ${f.direction === "risk" ? "bg-destructive" : "bg-success"}`}
                  style={{ width: `${(f.contribution / max) * 100}%` }}
                />
              </div>
              <div className="mt-1 text-[11px] text-muted-foreground">{f.explanation}</div>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

function SecurityIndicators({ heuristics, triggeredCount }: { heuristics: PA["heuristics"]; triggeredCount: number }) {
  return (
    <div className="rounded-2xl border border-border bg-card/60 p-5 backdrop-blur">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ClipboardList className="h-4 w-4 text-primary" />
          <h3 className="text-sm font-semibold">Security checklist</h3>
        </div>
        <span className="text-xs text-muted-foreground">{triggeredCount}/{heuristics.length} triggered</span>
      </div>
      <ul className="mt-4 grid gap-2 sm:grid-cols-2">
        {heuristics.map((h) => (
          <li
            key={h.label}
            className={`flex items-start gap-3 rounded-lg border px-3 py-2.5 text-sm transition ${
              h.triggered
                ? h.weight === "high" ? "border-destructive/40 bg-destructive/5"
                : h.weight === "medium" ? "border-warning/40 bg-warning/5"
                : "border-border bg-muted/40"
                : "border-border/50 bg-background/30 opacity-70"
            }`}
          >
            <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${
              h.triggered
                ? h.weight === "high" ? "bg-destructive"
                : h.weight === "medium" ? "bg-warning" : "bg-muted-foreground"
                : "bg-border"
            }`} />
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <span className="font-medium text-foreground">{h.label}</span>
                <span className="rounded border border-border px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-muted-foreground">{h.weight}</span>
              </div>
              <div className="mt-0.5 text-xs text-muted-foreground">{h.detail}</div>
              {h.triggered && <div className="mt-1 text-[11px] text-foreground/70">{h.explanation}</div>}
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

function FeatureBreakdown({ result }: { result: PA }) {
  const f = result.features;
  const items: { k: string; v: React.ReactNode }[] = [
    { k: "URL length", v: f.urlLength },
    { k: "Domain length", v: f.domainLength },
    { k: "Dots", v: f.numDots },
    { k: "Hyphens", v: f.numHyphens },
    { k: "Digits", v: f.numDigits },
    { k: "Special chars", v: f.numSpecialChars },
    { k: "Subdomains", v: f.numSubdomains },
    { k: "HTTPS", v: f.httpsStatus ? "Yes" : "No" },
    { k: "TLD", v: <>.{f.tld} <span className="text-[10px] text-muted-foreground">({f.tldType})</span></> },
    { k: "Entropy score", v: f.entropy },
    { k: "Encoded chars", v: f.encodedCharCount },
  ];
  return (
    <div className="rounded-2xl border border-border bg-card/60 p-5 backdrop-blur">
      <div className="mb-3 flex items-center gap-2">
        <BarChart3 className="h-4 w-4 text-primary" />
        <h3 className="text-sm font-semibold">URL feature breakdown</h3>
      </div>
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
        {items.map((it) => (
          <div key={it.k} className="rounded-lg border border-border/60 bg-background/30 p-3">
            <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{it.k}</div>
            <div className="mt-1 text-sm font-medium text-foreground">{it.v}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function RecommendationsPanel({ result }: { result: PA }) {
  return (
    <div className="rounded-2xl border border-border bg-card/60 p-5 backdrop-blur">
      <div className="mb-3 flex items-center gap-2">
        <ShieldCheck className="h-4 w-4 text-primary" />
        <h3 className="text-sm font-semibold">Security recommendations</h3>
      </div>
      <ul className="space-y-2">
        {result.recommendations.map((r, i) => (
          <li key={i} className="flex gap-2 text-sm text-foreground/90">
            <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-primary" />
            <span>{r}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

/* ---------- History Tab ---------- */

function HistoryTab({ history, onOpen }: { history: HE[]; onOpen: (a: PA) => void }) {
  const [q, setQ] = useState("");
  const [filter, setFilter] = useState<"all" | "favorites" | PA["verdict"]>("all");

  const filtered = useMemo(() => {
    return history.filter((h) => {
      if (filter === "favorites" && !h.favorite) return false;
      if (filter !== "all" && filter !== "favorites" && h.verdict !== filter) return false;
      if (q && !h.normalizedUrl.toLowerCase().includes(q.toLowerCase())) return false;
      return true;
    });
  }, [history, q, filter]);

  function exportAll() {
    const blob = new Blob([JSON.stringify(history, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `phishguard-history-${new Date().toISOString()}.json`;
    document.body.appendChild(a); a.click(); a.remove();
  }

  return (
    <section className="animate-fade-up">
      <h2 className="text-2xl font-semibold tracking-tight">Scan history</h2>
      <p className="mt-1 text-sm text-muted-foreground">Stored locally in your browser. {history.length} scan{history.length === 1 ? "" : "s"} recorded.</p>

      <div className="mt-6 flex flex-wrap items-center gap-2">
        <div className="flex flex-1 items-center gap-2 rounded-xl border border-border bg-card/60 px-3 py-2">
          <Search className="h-4 w-4 text-muted-foreground" />
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search URL…"
            className="w-full bg-transparent text-sm focus:outline-none" />
        </div>
        <select
          value={filter}
          onChange={(e) => setFilter(e.target.value as any)}
          className="rounded-xl border border-border bg-card/60 px-3 py-2 text-sm"
        >
          <option value="all">All</option>
          <option value="favorites">Favorites</option>
          <option value="safe">Safe</option>
          <option value="suspicious">Suspicious</option>
          <option value="dangerous">Dangerous</option>
        </select>
        <button onClick={exportAll} className="inline-flex items-center gap-1.5 rounded-xl border border-border bg-card/60 px-3 py-2 text-sm hover:border-primary/40">
          <FileJson className="h-4 w-4" />Export
        </button>
        <button onClick={() => confirm("Clear all history?") && clearHistory()} className="inline-flex items-center gap-1.5 rounded-xl border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive hover:bg-destructive/20">
          <Trash2 className="h-4 w-4" />Clear
        </button>
      </div>

      <ul className="mt-6 space-y-2">
        {filtered.length === 0 && (
          <li className="rounded-xl border border-dashed border-border p-6 text-center text-sm text-muted-foreground">
            No scans match your filter.
          </li>
        )}
        {filtered.map((h) => {
          const s = verdictStyle(h.verdict);
          return (
            <li key={h.id} className={`flex flex-wrap items-center gap-3 rounded-xl border ${s.border} bg-card/60 p-3`}>
              <div className={`flex h-9 w-9 items-center justify-center rounded-lg ${s.bg} ${s.color}`}>
                <s.Icon className="h-4 w-4" />
              </div>
              <div className="min-w-0 flex-1">
                <div className="truncate font-mono text-sm">{h.normalizedUrl}</div>
                <div className="mt-0.5 text-xs text-muted-foreground">
                  {new Date(h.analyzedAt).toLocaleString()} · risk {h.score}/100 · {h.confidence}% confidence
                </div>
              </div>
              <button onClick={() => toggleFavorite(h.id)} className="rounded-lg border border-border p-1.5 text-muted-foreground hover:text-warning" title="Toggle favorite">
                {h.favorite ? <Star className="h-4 w-4 fill-warning text-warning" /> : <StarOff className="h-4 w-4" />}
              </button>
              <button onClick={() => onOpen(h.analysis)} className="rounded-lg border border-border bg-background/40 px-3 py-1.5 text-xs hover:border-primary/40 hover:text-primary">
                View
              </button>
              <button onClick={() => deleteEntry(h.id)} className="rounded-lg border border-destructive/40 p-1.5 text-destructive hover:bg-destructive/10" title="Delete">
                <Trash2 className="h-4 w-4" />
              </button>
            </li>
          );
        })}
      </ul>
    </section>
  );
}

/* ---------- Analytics Tab ---------- */

function AnalyticsTab({ history }: { history: HE[] }) {
  const stats = useMemo(() => {
    const total = history.length;
    const safe = history.filter((h) => h.verdict === "safe").length;
    const susp = history.filter((h) => h.verdict === "suspicious").length;
    const dang = history.filter((h) => h.verdict === "dangerous").length;
    const avgConf = total ? Math.round(history.reduce((a, h) => a + h.confidence, 0) / total) : 0;
    const avgScore = total ? Math.round(history.reduce((a, h) => a + h.score, 0) / total) : 0;

    // Last 14 days chart
    const days = 14;
    const byDay: { day: string; count: number; dangerous: number }[] = [];
    const now = new Date();
    for (let i = days - 1; i >= 0; i--) {
      const d = new Date(now); d.setDate(d.getDate() - i);
      const key = d.toISOString().slice(0, 10);
      byDay.push({
        day: key,
        count: history.filter((h) => h.analyzedAt.slice(0, 10) === key).length,
        dangerous: history.filter((h) => h.analyzedAt.slice(0, 10) === key && h.verdict === "dangerous").length,
      });
    }
    return { total, safe, susp, dang, avgConf, avgScore, byDay };
  }, [history]);

  const maxDay = Math.max(1, ...stats.byDay.map((d) => d.count));

  return (
    <section className="animate-fade-up">
      <h2 className="text-2xl font-semibold tracking-tight">Analytics</h2>
      <p className="mt-1 text-sm text-muted-foreground">Aggregate stats across your local scan history.</p>

      <div className="mt-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard label="Total scans" value={stats.total} tone="neutral" />
        <StatCard label="Legitimate" value={stats.safe} tone="success" />
        <StatCard label="Suspicious" value={stats.susp} tone="warning" />
        <StatCard label="Phishing" value={stats.dang} tone="danger" />
        <StatCard label="Avg risk score" value={`${stats.avgScore}/100`} tone="neutral" />
        <StatCard label="Avg confidence" value={`${stats.avgConf}%`} tone="neutral" />
      </div>

      <div className="mt-6 rounded-2xl border border-border bg-card/60 p-5 backdrop-blur">
        <h3 className="mb-4 text-sm font-semibold">Scans — last 14 days</h3>
        <div className="flex h-40 items-end gap-1">
          {stats.byDay.map((d) => (
            <div key={d.day} className="group flex flex-1 flex-col items-center gap-1" title={`${d.day}: ${d.count} scan(s), ${d.dangerous} dangerous`}>
              <div className="relative w-full">
                <div className="w-full rounded-t bg-primary/70 transition-all" style={{ height: `${(d.count / maxDay) * 130}px` }} />
                {d.dangerous > 0 && (
                  <div className="absolute inset-x-0 bottom-0 rounded-t bg-destructive" style={{ height: `${(d.dangerous / maxDay) * 130}px` }} />
                )}
              </div>
              <div className="text-[9px] text-muted-foreground">{d.day.slice(5)}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="mt-6 rounded-2xl border border-border bg-card/60 p-5 backdrop-blur">
        <h3 className="mb-4 text-sm font-semibold">Risk distribution</h3>
        {stats.total === 0 ? (
          <p className="text-sm text-muted-foreground">No data yet — run a scan.</p>
        ) : (
          <div className="space-y-2">
            <DistRow label="Safe" count={stats.safe} total={stats.total} className="bg-success" />
            <DistRow label="Suspicious" count={stats.susp} total={stats.total} className="bg-warning" />
            <DistRow label="Dangerous" count={stats.dang} total={stats.total} className="bg-destructive" />
          </div>
        )}
      </div>
    </section>
  );
}

function StatCard({ label, value, tone }: { label: string; value: React.ReactNode; tone: "success" | "warning" | "danger" | "neutral" }) {
  const map = {
    success: "text-success", warning: "text-warning", danger: "text-destructive", neutral: "text-foreground",
  } as const;
  return (
    <div className="rounded-2xl border border-border bg-card/60 p-4 backdrop-blur">
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div>
      <div className={`mt-1 text-2xl font-semibold ${map[tone]}`}>{value}</div>
    </div>
  );
}

function DistRow({ label, count, total, className }: { label: string; count: number; total: number; className: string }) {
  const pct = total ? Math.round((count / total) * 100) : 0;
  return (
    <div>
      <div className="flex items-center justify-between text-xs">
        <span>{label}</span><span className="text-muted-foreground">{count} · {pct}%</span>
      </div>
      <div className="mt-1 h-2 overflow-hidden rounded-full bg-border">
        <div className={`h-full ${className} transition-all`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}
