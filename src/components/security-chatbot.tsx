import { useEffect, useRef, useState } from "react";
import { useServerFn } from "@tanstack/react-start";
import { MessageSquare, X, Send, Loader2, Bot, User as UserIcon } from "lucide-react";
import { askSecurityBot, type SecurityChatMessage } from "@/lib/security-chat.functions";
import type { PhishingAnalysis } from "@/lib/phishing.functions";

const SUGGESTIONS = [
  "Why is this website phishing?",
  "Explain this AI prediction.",
  "What is typosquatting?",
  "What is URL entropy?",
  "How can I identify phishing websites?",
  "Explain SSL certificates.",
];

function buildContext(result: PhishingAnalysis | null): string | undefined {
  if (!result) return undefined;
  const triggered = result.heuristics.filter((h) => h.triggered).map((h) => `${h.label} (${h.detail})`);
  return [
    `URL: ${result.normalizedUrl}`,
    `Verdict: ${result.verdict} · risk score ${result.score}/100 · confidence ${result.confidence}%`,
    `Threat level: ${result.threatLevel ?? "n/a"}`,
    `AI explanation: ${result.aiExplanation}`,
    `Domain age (days): ${result.metadata.domainAgeDays ?? "unknown"} · registrar: ${result.metadata.registrar ?? "unknown"}`,
    `HTTPS: ${result.features.httpsStatus} · entropy: ${result.features.entropy} · URL length: ${result.features.urlLength}`,
    `Threat feed: ${result.threatIntel.reported ? `reported (${result.threatIntel.threat})` : "not reported"}`,
    `Triggered signals: ${triggered.join("; ") || "none"}`,
    `Top model features: ${result.featureImportance.map((f) => `${f.feature} (${f.direction} ${f.contribution})`).join("; ")}`,
  ].join("\n");
}

export function SecurityChatbot({ result }: { result: PhishingAnalysis | null }) {
  const ask = useServerFn(askSecurityBot);
  const [open, setOpen] = useState(false);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [messages, setMessages] = useState<SecurityChatMessage[]>([
    {
      role: "assistant",
      content:
        "Hi — I'm the PhishGuard security assistant. Ask me why a site was flagged, or about phishing, HTTPS, SSL, typosquatting and URL entropy.",
    },
  ]);
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, open]);

  async function send(text: string) {
    const clean = text.trim();
    if (!clean || busy) return;
    const next: SecurityChatMessage[] = [...messages, { role: "user", content: clean }];
    setMessages(next);
    setInput("");
    setBusy(true);
    try {
      const { reply } = await ask({
        data: { messages: next.slice(-12), context: buildContext(result) },
      });
      setMessages((m) => [...m, { role: "assistant", content: reply }]);
    } catch (err) {
      setMessages((m) => [
        ...m,
        { role: "assistant", content: err instanceof Error ? err.message : "Something went wrong. Please try again." },
      ]);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <button
        onClick={() => setOpen((o) => !o)}
        aria-label="Open AI security assistant"
        className="fixed bottom-5 right-5 z-50 inline-flex h-13 items-center gap-2 rounded-full bg-primary px-4 py-3 text-sm font-semibold text-primary-foreground shadow-glow transition hover:brightness-110"
      >
        {open ? <X className="h-4 w-4" /> : <MessageSquare className="h-4 w-4" />}
        <span className="hidden sm:inline">{open ? "Close" : "Ask AI"}</span>
      </button>

      {open && (
        <div className="fixed bottom-20 right-5 z-50 flex h-[30rem] w-[min(24rem,calc(100vw-2.5rem))] flex-col overflow-hidden rounded-2xl border border-border bg-card/95 shadow-glow backdrop-blur-xl animate-fade-up">
          <div className="flex items-center gap-2 border-b border-border/60 px-4 py-3">
            <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-primary/15 text-primary">
              <Bot className="h-4 w-4" />
            </span>
            <div className="leading-tight">
              <div className="text-sm font-semibold">AI security assistant</div>
              <div className="text-[10px] uppercase tracking-wider text-muted-foreground">
                {result ? "Using your latest scan" : "General security help"}
              </div>
            </div>
          </div>

          <div className="flex-1 space-y-3 overflow-y-auto px-4 py-3">
            {messages.map((m, i) => (
              <div key={i} className={`flex gap-2 ${m.role === "user" ? "justify-end" : ""}`}>
                {m.role === "assistant" && <Bot className="mt-1 h-3.5 w-3.5 shrink-0 text-primary" />}
                <div
                  className={`max-w-[85%] whitespace-pre-wrap rounded-xl px-3 py-2 text-xs leading-relaxed ${
                    m.role === "user"
                      ? "bg-primary text-primary-foreground"
                      : "border border-border/60 bg-background/40 text-foreground/90"
                  }`}
                >
                  {m.content}
                </div>
                {m.role === "user" && <UserIcon className="mt-1 h-3.5 w-3.5 shrink-0 text-muted-foreground" />}
              </div>
            ))}
            {busy && (
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <Loader2 className="h-3.5 w-3.5 animate-spin text-primary" /> Thinking…
              </div>
            )}
            <div ref={endRef} />
          </div>

          <div className="border-t border-border/60 px-3 py-2">
            <div className="mb-2 flex gap-1.5 overflow-x-auto pb-1">
              {SUGGESTIONS.map((s) => (
                <button
                  key={s}
                  onClick={() => void send(s)}
                  disabled={busy}
                  className="shrink-0 rounded-full border border-border bg-background/40 px-2.5 py-1 text-[10px] text-muted-foreground transition hover:border-primary/40 hover:text-primary disabled:opacity-50"
                >
                  {s}
                </button>
              ))}
            </div>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                void send(input);
              }}
              className="flex items-center gap-2 rounded-xl bg-background/50 px-3 py-2"
            >
              <input
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder="Ask about this scan or phishing in general…"
                className="w-full bg-transparent text-xs text-foreground placeholder:text-muted-foreground focus:outline-none"
              />
              <button
                type="submit"
                disabled={busy || !input.trim()}
                className="inline-flex h-7 w-7 items-center justify-center rounded-lg bg-primary text-primary-foreground disabled:opacity-50"
              >
                <Send className="h-3.5 w-3.5" />
              </button>
            </form>
          </div>
        </div>
      )}
    </>
  );
}
