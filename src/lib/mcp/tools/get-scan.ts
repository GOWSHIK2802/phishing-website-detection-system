import { defineTool } from "@lovable.dev/mcp-js";
import { z } from "zod";
import { supabaseForUser } from "../supabase";

export default defineTool({
  name: "get_scan",
  title: "Get scan details",
  description:
    "Fetch the full stored analysis for one of the signed-in user's saved scans, including heuristics, URL features, domain metadata, threat intel and AI explanation.",
  inputSchema: { id: z.string().describe("The scan id returned by list_scans.") },
  annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
  handler: async ({ id }, ctx) => {
    if (!ctx.isAuthenticated()) {
      return { content: [{ type: "text", text: "Not authenticated" }], isError: true };
    }
    const supabase = supabaseForUser(ctx);
    const { data, error } = await supabase.from("scans").select("*").eq("id", id).maybeSingle();
    if (error) return { content: [{ type: "text", text: error.message }], isError: true };
    if (!data) return { content: [{ type: "text", text: "Scan not found." }], isError: true };

    return {
      content: [{ type: "text", text: JSON.stringify(data.analysis ?? data) }],
      structuredContent: { scan: data },
    };
  },
});
