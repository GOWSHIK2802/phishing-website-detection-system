import type { PhishingAnalysis } from "./phishing.functions";

const KEY = "phishguard.history.v1";
const MAX = 100;

export interface HistoryEntry {
  id: string;
  analyzedAt: string;
  url: string;
  normalizedUrl: string;
  verdict: PhishingAnalysis["verdict"];
  score: number;
  confidence: number;
  favorite: boolean;
  analysis: PhishingAnalysis;
}

function read(): HistoryEntry[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function write(entries: HistoryEntry[]) {
  if (typeof window === "undefined") return;
  try {
    localStorage.setItem(KEY, JSON.stringify(entries.slice(0, MAX)));
    window.dispatchEvent(new CustomEvent("phishguard:history-changed"));
  } catch {
    // storage quota — ignore
  }
}

export function getHistory(): HistoryEntry[] {
  return read();
}

export function addToHistory(analysis: PhishingAnalysis): HistoryEntry {
  const entries = read();
  const entry: HistoryEntry = {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    analyzedAt: analysis.analyzedAt,
    url: analysis.url,
    normalizedUrl: analysis.normalizedUrl,
    verdict: analysis.verdict,
    score: analysis.score,
    confidence: analysis.confidence,
    favorite: false,
    analysis,
  };
  write([entry, ...entries]);
  return entry;
}

export function deleteEntry(id: string) {
  write(read().filter((e) => e.id !== id));
}

export function toggleFavorite(id: string) {
  write(read().map((e) => (e.id === id ? { ...e, favorite: !e.favorite } : e)));
}

export function clearHistory() {
  write([]);
}
