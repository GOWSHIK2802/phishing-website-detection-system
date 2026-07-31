import { defineTool } from "@lovable.dev/mcp-js";
import { z } from "zod";
import { supabaseForUser } from "../supabase";

export default defineTool({
  name: "set_scan_favorite",
  title: "Favorite or unfavorite a scan",
  description: "Mark one of the signed-in user's saved scans as a favorite, or remove the favorite flag.",
  inputSchema: {
    id: z.string().describe("The scan id."),
    favorite: z.boolean().describe("true to favorite, false to unfavorite."),
  },
  annotations: { readOnlyHint: false, idempotentHint: true, openWorldHint: false },
  handler: async ({ id, favorite }, ctx) => {
    if (!ctx.isAuthenticated()) {
      return { content: [{ type: "text", text: "Not authenticated" }], isError: true };
    }
    const supabase = supabaseForUser(ctx);
    const { error } = await supabase.from("scans").update({ favorite }).eq("id", id);
    if (error) return { content: [{ type: "text", text: error.message }], isError: true };
    return {
      content: [{ type: "text", text: favorite ? "Scan favorited." : "Favorite removed." }],
      structuredContent: { id, favorite },
    };
  },
});
