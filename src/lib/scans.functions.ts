import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import type { PhishingAnalysis } from "./phishing.functions";

export interface ScanRecord {
  id: string;
  url: string;
  normalizedUrl: string;
  verdict: "safe" | "suspicious" | "dangerous";
  score: number;
  confidence: number;
  favorite: boolean;
  analyzedAt: string;
  analysis: PhishingAnalysis;
}

const SaveInput = z.object({
  url: z.string(),
  normalizedUrl: z.string(),
  verdict: z.enum(["safe", "suspicious", "dangerous"]),
  score: z.number().int(),
  confidence: z.number().int(),
  analysis: z.any(),
  analyzedAt: z.string(),
});

export const listScans = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }): Promise<ScanRecord[]> => {
    const { data, error } = await context.supabase
      .from("scans")
      .select("*")
      .order("created_at", { ascending: false })
      .limit(200);
    if (error) throw new Error(error.message);
    return (data ?? []).map((r: any) => ({
      id: r.id,
      url: r.url,
      normalizedUrl: r.normalized_url,
      verdict: r.verdict,
      score: r.score,
      confidence: r.confidence,
      favorite: r.favorite,
      analyzedAt: r.analyzed_at,
      analysis: r.analysis,
    }));
  });

export const saveScan = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: unknown) => SaveInput.parse(d))
  .handler(async ({ data, context }) => {
    const { error } = await context.supabase.from("scans").insert({
      user_id: context.userId,
      url: data.url,
      normalized_url: data.normalizedUrl,
      verdict: data.verdict,
      score: data.score,
      confidence: data.confidence,
      analysis: data.analysis,
      analyzed_at: data.analyzedAt,
    });
    if (error) throw new Error(error.message);
    return { ok: true };
  });

export const deleteScan = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: unknown) => z.object({ id: z.string() }).parse(d))
  .handler(async ({ data, context }) => {
    const { error } = await context.supabase.from("scans").delete().eq("id", data.id);
    if (error) throw new Error(error.message);
    return { ok: true };
  });

export const setScanFavorite = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: unknown) => z.object({ id: z.string(), favorite: z.boolean() }).parse(d))
  .handler(async ({ data, context }) => {
    const { error } = await context.supabase
      .from("scans")
      .update({ favorite: data.favorite })
      .eq("id", data.id);
    if (error) throw new Error(error.message);
    return { ok: true };
  });

export const clearScans = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { error } = await context.supabase
      .from("scans")
      .delete()
      .eq("user_id", context.userId);
    if (error) throw new Error(error.message);
    return { ok: true };
  });
