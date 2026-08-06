import { useEffect, useState } from "react";
import type { PhishingAnalysis } from "@/lib/phishing.functions";
import {
  ShieldCheck, ShieldAlert, ShieldX, Gauge, Radar, Flame, CalendarClock, Timer,
} from "lucide-react";

export function threatLevelOf(result: PhishingAnalysis) {
  if (result.threatLevel) return result.threatLevel;
  if (result.threatIntel?.reported || result.score >= 85) return "critical" as const;
  if (result.score >= 65) return "high" as const;
  if (result.score >= 30) return "medium" as const;
  return "low" as const;
}

const LEVEL_STYLE = {
  low: { label: "Low", cls: "text-success", chip: "border-success/40 bg-success/10 text-success" },
  medium: { label: "Medium", cls: "text-warning", chip: "border-warning/40 bg-warning/10 text-warning" },
  high: { label: "High", cls: "text-destructive", chip: "border-destructive/40 bg-destructive/10 text-destructive" },
  critical: { label: "Critical", cls: "text-destructive", chip: "border-destructive/60 bg-destructive/20 text-destructive" },
} as const;

/** Animated circular risk meter — sweeps from 0 to the score on every new scan. */
export function ThreatMeter({ score, verdict }: { score: number; verdict: PhishingAnalysis["verdict"] }) {
  const [shown, setShown] = useState(0);
  useEffect(() => {
    setShown(0);
    const id = requestAnimationFrame(() => setShown(score));
    return () => cancelAnimationFrame(id);
  }, [score]);

  const color = verdict === "dangerous" ? "text-destructive" : verdict === "suspicious" ? "text-warning" : "text-success";
  const r = 52;
  const c = 2 * Math.PI * r;
  const offset = c - (shown / 100) * c;

  return (
    <div className="relative flex h-40 w-40 items-center justify-center">
      <svg viewBox="0 0 120 120" className="h-40 w-40 -rotate-90">
        <circle cx="60" cy="60" r={r} strokeWidth="10" className="fill-none stroke-border" />
        <circle
          cx="60" cy="60" r={r} strokeWidth="10" strokeLinecap="round"
          strokeDasharray={c} strokeDashoffset={offset} stroke="currentColor"
          className={`fill-none ${color} transition-[stroke-dashoffset] duration-1000 ease-out`}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <div className={`text-3xl font-semibold tabular-nums ${color}`}>{Math.round(shown)}</div>
        <div className="text-[10px] uppercase tracking-[0.18em] text-muted-foreground">risk score</div>
      </div>
    </div>
  );
}

function Card({
  icon, label, value, sub, tone = "",
}: { icon: React.ReactNode; label: string; value: React.ReactNode; sub?: string; tone?: string }) {
  return (
    <div className="rounded-2xl border border-border bg-card/60 p-4 backdrop-blur transition hover:border-primary/40">
      <div className="flex items-center gap-2 text-[10px] uppercase tracking-[0.16em] text-muted-foreground">
        <span className="text-primary">{icon}</span>
        {label}
      </div>
      <div className={`mt-2 text-lg font-semibold ${tone || "text-foreground"}`}>{value}</div>
      {sub && <div className="mt-0.5 text-[11px] text-muted-foreground">{sub}</div>}
    </div>
  );
}

export function DetectionSummary({ result }: { result: PhishingAnalysis }) {
  const level = LEVEL_STYLE[threatLevelOf(result)];
  const statusLabel = result.verdict === "dangerous" ? "Phishing" : result.verdict === "suspicious" ? "Suspicious" : "Safe";
  const StatusIcon = result.verdict === "dangerous" ? ShieldX : result.verdict === "suspicious" ? ShieldAlert : ShieldCheck;
  const statusTone = result.verdict === "dangerous" ? "text-destructive" : result.verdict === "suspicious" ? "text-warning" : "text-success";
  const when = new Date(result.analyzedAt);
  const duration = result.scanDurationMs;

  return (
    <div className="rounded-2xl border border-border bg-card/60 p-5 backdrop-blur">
      <div className="mb-4 flex items-center gap-2">
        <Gauge className="h-4 w-4 text-primary" />
        <h3 className="text-sm font-semibold">AI security report</h3>
        <span className={`ml-auto rounded-full border px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider ${level.chip}`}>
          {level.label} threat
        </span>
      </div>
      <div className="grid gap-5 lg:grid-cols-[auto_1fr] lg:items-center">
        <div className="flex justify-center">
          <ThreatMeter score={result.score} verdict={result.verdict} />
        </div>
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          <Card icon={<StatusIcon className="h-3.5 w-3.5" />} label="Website status" value={statusLabel} tone={statusTone} sub={result.normalizedUrl.replace(/^https?:\/\//, "").slice(0, 42)} />
          <Card icon={<Flame className="h-3.5 w-3.5" />} label="AI risk score" value={`${result.score}%`} tone={statusTone} sub="0 = safe · 100 = confirmed phishing" />
          <Card icon={<Radar className="h-3.5 w-3.5" />} label="AI confidence" value={`${result.confidence}%`} sub="Model certainty in this verdict" />
          <Card icon={<ShieldAlert className="h-3.5 w-3.5" />} label="Threat level" value={level.label} tone={level.cls} sub="Low · Medium · High · Critical" />
          <Card icon={<CalendarClock className="h-3.5 w-3.5" />} label="Scan date & time" value={when.toLocaleDateString()} sub={when.toLocaleTimeString()} />
          <Card icon={<Timer className="h-3.5 w-3.5" />} label="Scan duration" value={duration != null ? `${(duration / 1000).toFixed(2)}s` : "—"} sub="End-to-end analysis time" />
        </div>
      </div>
    </div>
  );
}
