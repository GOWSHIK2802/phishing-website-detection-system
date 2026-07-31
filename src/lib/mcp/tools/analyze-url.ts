import { defineTool } from "@lovable.dev/mcp-js";
import { z } from "zod";
import { analyzeUrl } from "@/lib/phishing.functions";
import { supabaseForUser } from "../supabase";

export default defineTool({
  name: "analyze_url",
  title: "Analyze URL for phishing",
  description:
    "Run the PhishGuard AI phishing analysis on a URL. Returns a risk score (0-100), verdict, confidence, red flags, security heuristics, URL features, domain metadata and threat-intelligence results. Optionally saves the scan to the signed-in user's history.",
  inputSchema: {
    url: z.string().describe("The website URL to analyze, e.g. https://example.com"),
    save: z
      .boolean()
      .optional()
      .describe("Save the result to the signed-in user's scan history (default true)."),
  },
  annotations: { readOnlyHint: false, openWorldHint: true },
  handler: async ({ url, save }, ctx) => {
    if (!ctx.isAuthenticated()) {
      return { content: [{ type: "text", text: "Not authenticated" }], isError: true };
    }

    let analysis;
    try {
      analysis = await analyzeUrl({ data: { url } });
    } catch (error) {
      return {
        content: [
          { type: "text", text: error instanceof Error ? error.message : "Analysis failed." },
        ],
        isError: true,
      };
    }

    let saved = false;
    if (save !== false) {
      const supabase = supabaseForUser(ctx);
      const { error } = await supabase.from("scans").insert({
        user_id: ctx.getUserId(),
        url: analysis.url,
        normalized_url: analysis.normalizedUrl,
        verdict: analysis.verdict,
        score: analysis.score,
        confidence: analysis.confidence,
        analysis,
        analyzed_at: analysis.analyzedAt,
      });
      saved = !error;
    }

    const summary = [
      `URL: ${analysis.normalizedUrl}`,
      `Verdict: ${analysis.verdict.toUpperCase()} (risk score ${analysis.score}/100, confidence ${analysis.confidence}%)`,
      `Summary: ${analysis.summary}`,
      analysis.redFlags.length
        ? `Red flags:\n${analysis.redFlags.map((f) => `- ${f.label}: ${f.explanation}`).join("\n")}`
        : "Red flags: none detected",
      `Recommendation: ${analysis.recommendation}`,
      saved ? "Saved to scan history." : "",
    ]
      .filter(Boolean)
      .join("\n\n");

    return {
      content: [{ type: "text", text: summary }],
      structuredContent: { saved, analysis: analysis as unknown as Record<string, unknown> },
    };
  },
});
