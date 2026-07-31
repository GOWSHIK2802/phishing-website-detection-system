import { auth, defineMcp } from "@lovable.dev/mcp-js";
import analyzeUrlTool from "./tools/analyze-url";
import listScansTool from "./tools/list-scans";
import getScanTool from "./tools/get-scan";
import setScanFavoriteTool from "./tools/set-scan-favorite";
import deleteScanTool from "./tools/delete-scan";

const projectRef = import.meta.env['VITE_SUPABASE_PROJECT_ID'] ?? "project-ref-unset";

export default defineMcp({
  name: "phish-guard-ai",
  title: "Phish Guard AI",
  version: "0.1.0",
  instructions:
    "Tools for Phish Guard AI, a phishing website detection system. Use `analyze_url` to score a URL for phishing risk and get explainable red flags. Use `list_scans`, `get_scan`, `set_scan_favorite`, and `delete_scan` to work with the signed-in user's saved scan history.",
  auth: auth.oauth.issuer({
    issuer: `https://${projectRef}.supabase.co/auth/v1`,
    acceptedAudiences: "authenticated",
  }),
  tools: [analyzeUrlTool, listScansTool, getScanTool, setScanFavoriteTool, deleteScanTool],
});
