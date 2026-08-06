import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";

const MessageSchema = z.object({
  role: z.enum(["user", "assistant"]),
  content: z.string().min(1).max(4000),
});

const InputSchema = z.object({
  messages: z.array(MessageSchema).min(1).max(24),
  context: z.string().max(6000).optional(),
});

export type SecurityChatMessage = z.infer<typeof MessageSchema>;

export const askSecurityBot = createServerFn({ method: "POST" })
  .inputValidator((data: unknown) => InputSchema.parse(data))
  .handler(async ({ data }): Promise<{ reply: string }> => {
    const apiKey = process.env.LOVABLE_API_KEY;
    if (!apiKey) throw new Error("Missing LOVABLE_API_KEY");

    const systemPrompt = `You are PhishGuard AI's security assistant. You explain phishing detection, URL security concepts (typosquatting, URL entropy, HTTPS, SSL certificates, URL shorteners, redirect chains, WHOIS/domain age), and how the XGBoost + heuristic model in this app reaches its verdicts.

Rules:
- Answer in clear, friendly, plain language. Keep answers under 180 words.
- Use short markdown bullet lists when listing reasons.
- When scan context is provided, ground your answer in that specific scan's data.
- Never tell a user it is safe to enter credentials on a flagged site.
- If asked something unrelated to security or this app, politely redirect.

${data.context ? `Current scan context:\n${data.context}` : "No scan has been run yet in this session."}`;

    const response = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Lovable-API-Key": apiKey },
      body: JSON.stringify({
        model: "google/gemini-3-flash-preview",
        messages: [{ role: "system", content: systemPrompt }, ...data.messages],
      }),
    });

    if (response.status === 429) throw new Error("Rate limit reached. Please try again in a moment.");
    if (response.status === 402) throw new Error("AI credits exhausted. Please add credits in Lovable Cloud.");
    if (!response.ok) {
      const text = await response.text().catch(() => "");
      throw new Error(`AI gateway error (${response.status}): ${text.slice(0, 200)}`);
    }

    const payload = await response.json();
    const reply: string = payload?.choices?.[0]?.message?.content ?? "Sorry, I couldn't generate an answer.";
    return { reply };
  });
