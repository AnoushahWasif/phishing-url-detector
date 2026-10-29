export type Label = "phishing" | "legitimate" | "unknown";

export type Verdict = {
  host: string;
  label: Label;
  score: number | null;
  threshold: number;
  reasons: string[];
};

export const MAX_REASONS = 5;
export const MAX_REASON_LENGTH = 200;
const LABELS: readonly string[] = ["phishing", "legitimate", "unknown"];

export class VerdictError extends Error {}

function probability(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1;
}

/**
 * Checks the shape of a /score response. Wrong types are rejected; long reason lists
 * are trimmed rather than rejected, so a chatty API can't suppress a phishing warning.
 */
export function parseVerdict(data: unknown): Verdict {
  if (typeof data !== "object" || data === null || Array.isArray(data)) {
    throw new VerdictError("not an object");
  }
  const d = data as Record<string, unknown>;
  if (typeof d.host !== "string" || d.host.length === 0 || d.host.length > 253) {
    throw new VerdictError("bad host");
  }
  if (typeof d.label !== "string" || !LABELS.includes(d.label)) {
    throw new VerdictError("bad label");
  }
  if (d.score !== null && !probability(d.score)) throw new VerdictError("bad score");
  if (!probability(d.threshold)) throw new VerdictError("bad threshold");
  if (!Array.isArray(d.reasons) || !d.reasons.every((r) => typeof r === "string")) {
    throw new VerdictError("bad reasons");
  }
  return {
    host: d.host,
    label: d.label as Label,
    score: d.score,
    threshold: d.threshold,
    reasons: (d.reasons as string[]).slice(0, MAX_REASONS).map((r) => r.slice(0, MAX_REASON_LENGTH)),
  };
}
