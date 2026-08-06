import type { PhishingAnalysis } from "@/lib/phishing.functions";
import { Globe2, Server, Building2, CalendarPlus, CalendarX, MapPin, Network, Lock, ShieldCheck, Clock } from "lucide-react";

function InfoCard({ icon, label, value, tone }: { icon: React.ReactNode; label: string; value: React.ReactNode; tone?: string }) {
  return (
    <div className="rounded-xl border border-border/60 bg-background/30 p-3.5 transition hover:border-primary/40">
      <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-[0.14em] text-muted-foreground">
        <span className="text-primary">{icon}</span>
        {label}
      </div>
      <div className={`mt-1.5 break-words text-sm font-medium ${tone ?? "text-foreground"}`}>{value}</div>
    </div>
  );
}

function fmt(iso: string | null | undefined) {
  if (!iso) return "Unknown";
  try { return new Date(iso).toLocaleDateString(); } catch { return iso; }
}

export function WebsiteInfoPanel({ result }: { result: PhishingAnalysis }) {
  const m = result.metadata;
  const dns = result.dns;
  const https = result.features.httpsStatus;
  const sslOk = https && m.ssl.httpsReachable;

  return (
    <div className="rounded-2xl border border-border bg-card/60 p-5 backdrop-blur">
      <div className="mb-4 flex items-center gap-2">
        <Globe2 className="h-4 w-4 text-primary" />
        <h3 className="text-sm font-semibold">Website information</h3>
      </div>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        <InfoCard icon={<Globe2 className="h-3.5 w-3.5" />} label="Domain name" value={<span className="font-mono">{m.registrableDomain}</span>} />
        <InfoCard
          icon={<Clock className="h-3.5 w-3.5" />}
          label="Domain age"
          value={m.domainAgeDays !== null ? `${m.domainAgeDays} days (${Math.floor(m.domainAgeDays / 365)}y)` : "Unknown"}
          tone={m.domainAgeDays !== null && m.domainAgeDays < 180 ? "text-warning" : undefined}
        />
        <InfoCard icon={<Building2 className="h-3.5 w-3.5" />} label="Registrar" value={m.registrar ?? "Unknown"} />
        <InfoCard icon={<CalendarPlus className="h-3.5 w-3.5" />} label="Creation date" value={fmt(m.registrationDate)} />
        <InfoCard icon={<CalendarX className="h-3.5 w-3.5" />} label="Expiry date" value={fmt(m.expirationDate)} />
        <InfoCard icon={<Server className="h-3.5 w-3.5" />} label="IP address" value={<span className="font-mono">{dns?.ipAddress ?? "Unresolved"}</span>} />
        <InfoCard icon={<MapPin className="h-3.5 w-3.5" />} label="Hosting country" value={dns?.hostingCountry ?? m.hostingCountry ?? "Unknown"} />
        <InfoCard
          icon={<Network className="h-3.5 w-3.5" />}
          label="DNS status"
          value={dns ? dns.status : "Not checked"}
          tone={dns?.resolved ? "text-success" : "text-warning"}
        />
        <InfoCard
          icon={<Lock className="h-3.5 w-3.5" />}
          label="HTTPS status"
          value={https ? "Enabled" : "Not used"}
          tone={https ? "text-success" : "text-destructive"}
        />
        <InfoCard
          icon={<ShieldCheck className="h-3.5 w-3.5" />}
          label="SSL certificate"
          value={sslOk ? "Valid TLS handshake" : https ? "Not verifiable" : "No certificate"}
          tone={sslOk ? "text-success" : "text-warning"}
        />
        {dns?.hostingOrg && <InfoCard icon={<Building2 className="h-3.5 w-3.5" />} label="Hosting provider" value={dns.hostingOrg} />}
        {m.nameservers.length > 0 && (
          <InfoCard icon={<Server className="h-3.5 w-3.5" />} label="Nameservers" value={<span className="font-mono text-xs">{m.nameservers.slice(0, 2).join(", ")}</span>} />
        )}
      </div>
    </div>
  );
}
