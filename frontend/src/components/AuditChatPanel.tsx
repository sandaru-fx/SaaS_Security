"use client";

import { FormEvent, useState } from "react";

import { AuditChatMessage, chatWithAudit } from "@/lib/api";

type AuditChatPanelProps = {
  scanId: string;
  getToken: () => Promise<string | null>;
  deepAuditEnabled: boolean;
};

export function AuditChatPanel({ scanId, getToken, deepAuditEnabled }: AuditChatPanelProps) {
  const [messages, setMessages] = useState<AuditChatMessage[]>([
    {
      role: "assistant",
      content:
        "Ask me about this audit — top risks, score, false positives, or how to fix specific findings.",
    },
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [provider, setProvider] = useState<string | null>(null);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    const text = input.trim();
    if (!text || loading) return;

    const history = messages
      .slice(1)
      .filter((m) => m.role === "user" || m.role === "assistant")
      .slice(-10);

    const userMessage: AuditChatMessage = { role: "user", content: text };
    setMessages((prev) => [...prev, userMessage]);
    setInput("");
    setLoading(true);

    try {
      const token = await getToken();
      if (!token) throw new Error("Not authenticated");
      const response = await chatWithAudit(token, scanId, {
        message: text,
        history,
      });
      setProvider(response.provider);
      setMessages((prev) => [...prev, { role: "assistant", content: response.reply }]);
    } catch (err) {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: err instanceof Error ? err.message : "Chat request failed",
        },
      ]);
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="mt-8 rounded-2xl border border-indigo-500/20 bg-indigo-950/20 p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="text-lg font-semibold text-zinc-50">Chat with Audit</h3>
          <p className="mt-1 text-sm text-zinc-400">
            Ask questions about findings, priorities, and remediation.
          </p>
        </div>
        {provider && (
          <span className="rounded-full border border-zinc-700 px-3 py-1 text-xs text-zinc-400">
            {provider === "rule-based" ? "Basic assistant" : `AI: ${provider}`}
          </span>
        )}
      </div>

      {!deepAuditEnabled && (
        <p className="mt-3 text-xs text-amber-300">
          Free plan uses rule-based answers. Upgrade to Pro for full AI chat powered by Gemini.
        </p>
      )}

      <div className="mt-4 max-h-80 space-y-3 overflow-y-auto rounded-xl border border-zinc-800 bg-zinc-950/60 p-4">
        {messages.map((msg, index) => (
          <div
            key={`${msg.role}-${index}`}
            className={`rounded-lg px-4 py-3 text-sm leading-relaxed ${
              msg.role === "user"
                ? "ml-8 bg-emerald-500/10 text-emerald-100"
                : "mr-8 bg-zinc-900 text-zinc-300"
            }`}
          >
            {msg.content}
          </div>
        ))}
        {loading && (
          <p className="text-sm text-zinc-500">Thinking...</p>
        )}
      </div>

      <form onSubmit={handleSubmit} className="mt-4 flex gap-2">
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="e.g. What are the top 3 risks?"
          className="flex-1 rounded-lg border border-zinc-700 bg-zinc-900 px-4 py-2.5 text-sm text-zinc-50 outline-none focus:border-indigo-500"
        />
        <button
          type="submit"
          disabled={loading || !input.trim()}
          className="rounded-lg bg-indigo-500 px-4 py-2.5 text-sm font-semibold text-white hover:bg-indigo-400 disabled:opacity-50"
        >
          Send
        </button>
      </form>
    </section>
  );
}
