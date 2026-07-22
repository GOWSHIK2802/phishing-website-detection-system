import { createFileRoute, useNavigate, Link } from "@tanstack/react-router";
import { useEffect, useState, type FormEvent } from "react";
import { Shield, Loader2, Mail, Lock, LogIn, UserPlus, ArrowLeft } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { lovable } from "@/integrations/lovable/index";

export const Route = createFileRoute("/auth")({
  head: () => ({
    meta: [
      { title: "Sign in — PhishGuard AI" },
      { name: "description", content: "Sign in to PhishGuard AI to save your scan history and sync across devices." },
      { property: "og:title", content: "Sign in — PhishGuard AI" },
      { property: "og:description", content: "Sign in to save and sync your phishing scan history." },
      { property: "og:type", content: "website" },
    ],
  }),
  component: AuthPage,
});

function AuthPage() {
  const navigate = useNavigate();
  const [mode, setMode] = useState<"signin" | "signup">("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);

  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => {
      if (data.session) navigate({ to: "/" });
    });
  }, [navigate]);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null); setInfo(null); setLoading(true);
    try {
      if (mode === "signin") {
        const { error } = await supabase.auth.signInWithPassword({ email, password });
        if (error) throw error;
        navigate({ to: "/" });
      } else {
        const { data, error } = await supabase.auth.signUp({
          email, password,
          options: { emailRedirectTo: window.location.origin },
        });
        if (error) throw error;
        if (data.session) navigate({ to: "/" });
        else setInfo("Check your email to confirm your account.");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Authentication failed.");
    } finally {
      setLoading(false);
    }
  }

  async function onGoogle() {
    setError(null); setLoading(true);
    try {
      const result = await lovable.auth.signInWithOAuth("google", {
        redirect_uri: window.location.origin,
      });
      if (result.error) throw result.error;
      if (!result.redirected) navigate({ to: "/" });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Google sign-in failed.");
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-hero">
      <div className="min-h-screen bg-background/40 backdrop-blur-[1px]">
        <div className="mx-auto max-w-md px-6 py-12">
          <Link to="/" className="mb-8 inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground">
            <ArrowLeft className="h-4 w-4" /> Back
          </Link>

          <div className="rounded-2xl border border-border bg-card/80 p-6 shadow-glow backdrop-blur-md">
            <div className="flex items-center gap-2.5">
              <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-primary/15 text-primary shadow-glow">
                <Shield className="h-5 w-5" />
              </div>
              <div>
                <div className="text-sm font-semibold">PhishGuard AI</div>
                <div className="text-[11px] uppercase tracking-[0.15em] text-muted-foreground">
                  {mode === "signin" ? "Sign in" : "Create account"}
                </div>
              </div>
            </div>

            <button
              onClick={onGoogle}
              disabled={loading}
              className="mt-6 flex w-full items-center justify-center gap-2 rounded-xl border border-border bg-background/40 px-4 py-2.5 text-sm font-medium hover:border-primary/40 disabled:opacity-60"
            >
              <svg className="h-4 w-4" viewBox="0 0 24 24"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1Z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.99.67-2.26 1.06-3.71 1.06-2.86 0-5.28-1.93-6.15-4.52H2.18v2.84A11 11 0 0 0 12 23Z"/><path fill="#FBBC05" d="M5.85 14.11a6.6 6.6 0 0 1 0-4.22V7.05H2.18a11 11 0 0 0 0 9.9l3.67-2.84Z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.2 1.65l3.15-3.15C17.45 2.13 14.97 1 12 1A11 11 0 0 0 2.18 7.05l3.67 2.84C6.72 7.31 9.14 5.38 12 5.38Z"/></svg>
              Continue with Google
            </button>

            <div className="my-5 flex items-center gap-3 text-[11px] uppercase tracking-wider text-muted-foreground">
              <span className="h-px flex-1 bg-border" /> or <span className="h-px flex-1 bg-border" />
            </div>

            <form onSubmit={onSubmit} className="space-y-3">
              <label className="block">
                <span className="mb-1 block text-xs uppercase tracking-wider text-muted-foreground">Email</span>
                <div className="flex items-center gap-2 rounded-xl border border-border bg-background/40 px-3 py-2.5">
                  <Mail className="h-4 w-4 text-muted-foreground" />
                  <input type="email" required value={email} onChange={(e) => setEmail(e.target.value)}
                    className="w-full bg-transparent text-sm focus:outline-none" placeholder="you@example.com" />
                </div>
              </label>
              <label className="block">
                <span className="mb-1 block text-xs uppercase tracking-wider text-muted-foreground">Password</span>
                <div className="flex items-center gap-2 rounded-xl border border-border bg-background/40 px-3 py-2.5">
                  <Lock className="h-4 w-4 text-muted-foreground" />
                  <input type="password" required minLength={6} value={password} onChange={(e) => setPassword(e.target.value)}
                    className="w-full bg-transparent text-sm focus:outline-none" placeholder="••••••••" />
                </div>
              </label>

              {error && <div className="rounded-lg border border-destructive/40 bg-destructive/10 p-2.5 text-xs text-destructive">{error}</div>}
              {info && <div className="rounded-lg border border-primary/40 bg-primary/10 p-2.5 text-xs text-primary">{info}</div>}

              <button type="submit" disabled={loading}
                className="mt-1 inline-flex w-full items-center justify-center gap-2 rounded-xl bg-primary px-4 py-2.5 text-sm font-semibold text-primary-foreground transition hover:brightness-110 disabled:opacity-60">
                {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : mode === "signin" ? <LogIn className="h-4 w-4" /> : <UserPlus className="h-4 w-4" />}
                {mode === "signin" ? "Sign in" : "Create account"}
              </button>
            </form>

            <div className="mt-4 text-center text-xs text-muted-foreground">
              {mode === "signin" ? "New here?" : "Already have an account?"}{" "}
              <button onClick={() => { setMode(mode === "signin" ? "signup" : "signin"); setError(null); setInfo(null); }}
                className="font-medium text-primary hover:underline">
                {mode === "signin" ? "Create an account" : "Sign in"}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
