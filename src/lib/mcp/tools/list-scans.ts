import { defineTool } from "@lovable.dev/mcp-js";
import { z } from "zod";
import { supabaseForUser } from "../supabase";

export default defineTool({
  name: "list_scans",
  title: "List scan history",
  description:
    "List the signed-in user's saved phishing scans, newest first. Optionally filter by verdict, favorites, or a URL substring.",
  inputSchema: {
    limit: z.number().int().optional().describe("Max rows to return (default 20, max 100)."),
    verdict: z.enum(["safe", "suspicious", "dangerous"]).optional().describe("Filter by verdict."),
    favoritesOnly: z.boolean().optional().describe("Only return favorited scans."),
    search: z.string().optional().describe("Case-insensitive substring match on the URL."),
  },
  annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
  handler: async ({ limit, verdict, favoritesOnly, search }, ctx) => {
    if (!ctx.isAuthenticated()) {
      return { content: [{ type: "text", text: "Not authenticated" }], isError: true };
    }
    const supabase = supabaseForUser(ctx);
    let query = supabase
      .from("scans")
      .select("id, url, normalized_url, verdict, score, confidence, favorite, analyzed_at")
      .order("created_at", { ascending: false })
      .limit(Math.min(Math.max(limit ?? 20, 1), 100));

    if (verdict) query = query.eq("verdict", verdict);
    if (favoritesOnly) query = query.eq("favorite", true);
    if (search) query = query.ilike("url", `%${search}%`);

    const { data, error } = await query;
    if (error) return { content: [{ type: "text", text: error.message }], isError: true };

    const rows = data ?? [];
    const text = rows.length
      ? rows
          .map(
            (r) =>
              `${r.verdict.toUpperCase()} ${r.score}/100 — ${r.url}${r.favorite ? " ★" : ""} (${r.analyzed_at}) [id: ${r.id}]`,
          )
          .join("\n")
      : "No scans found.";

    return { content: [{ type: "text", text }], structuredContent: { scans: rows } };
  },
});
