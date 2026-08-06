import type { PhishingAnalysis, ServiceStatus } from "@/lib/phishing.functions";
import { Radar, CheckCircle2, AlertOctagon, MinusCircle, Info } from "lucide-react";

const STATUS = {
  safe: { label: "Safe", cls: "border-success/40 bg-success/10 text-success", Icon: CheckCircle2 },
  detected: { label: "Detected", cls: "border-destructive/50 bg-destructive/15 text-destructive", Icon: AlertOctagon },
  unavailable: { label: "Unavailable", cls: "border-border bg-muted/40 text-muted-foreground", Icon: MinusCircle },
  info: { label: "Checked", cls: "border-primary/40 bg-primary/10 text-primary", Icon: Info },
} as const satisfies Record<ServiceStatus, unknown>;

export function ThreatIntelligenceGrid({ result }: { result: PhishingAnalysis }) {
  const services = result.threatServices ?? [];
  if (services.length === 0) return null;
  const detected = services.filter((s) => s.status === "detected").length;

  return (
    <div className="rounded-2xl border border-border bg-card/60 p-5 backdrop-blur">
      <div className="mb-4 flex items-center gap-2">
        <Radar className="h-4 w-4 text-primary" />
        <h3 className="text-sm font-semibold">Threat intelligence sources</h3>
        <span className={`ml-auto text-xs ${detected ? "text-destructive" : "text-muted-foreground"}`}>
          {detected ? `${detected} source${detected > 1 ? "s" : ""} flagged this URL` : "No source flagged this URL"}
        </span>
      </div>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {services.map((s) => {
          const st = STATUS[s.status] ?? STATUS.unavailable;
          const { Icon } = st;
          return (
            <div key={s.name} className="rounded-xl border border-border/60 bg-background/30 p-3.5 transition hover:border-primary/40">
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm font-medium text-foreground">{s.name}</span>
                <span className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] uppercase tracking-wide ${st.cls}`}>
                  <Icon className="h-3 w-3" />{st.label}
                </span>
              </div>
              <p className="mt-1.5 text-[11px] leading-relaxed text-muted-foreground">{s.detail}</p>
              <div className="mt-1 text-[10px] text-muted-foreground/70">
                Checked {new Date(s.checkedAt).toLocaleTimeString()}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
