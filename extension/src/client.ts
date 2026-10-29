import { API_BASE, DEFAULT_BACKOFF_MS, MAX_RESPONSE_BYTES, TIMEOUT_MS } from "./config";
import { parseVerdict, type Verdict } from "./verdict";

export type ScoreErrorKind = "network" | "timeout" | "rate_limited" | "http" | "invalid";

export class ScoreError extends Error {
  constructor(
    readonly kind: ScoreErrorKind,
    readonly retryAfterMs?: number,
  ) {
    super(kind);
  }
}

type Options = { base?: string; fetchImpl?: typeof fetch; timeoutMs?: number };

function retryAfter(header: string | null): number {
  const seconds = Number(header);
  // Capped so a hostile or broken header can't switch checks off for hours.
  return Number.isFinite(seconds) && seconds > 0 ? Math.min(seconds, 600) * 1000 : DEFAULT_BACKOFF_MS;
}

export async function scoreUrl(target: string, options: Options = {}): Promise<Verdict> {
  const { base = API_BASE, fetchImpl = fetch, timeoutMs = TIMEOUT_MS } = options;
  // One timer covers headers and body, so a server that stalls mid-body still times out.
  const timeout = new AbortController();
  const timer = setTimeout(() => timeout.abort(), timeoutMs);
  const failure = (kind: ScoreErrorKind) => new ScoreError(timeout.signal.aborted ? "timeout" : kind);

  let text: string;
  try {
    let response: Response;
    try {
      response = await fetchImpl(`${base}/score`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({ url: target }),
        signal: timeout.signal,
        credentials: "omit",
        redirect: "error",
        cache: "no-store",
      });
    } catch {
      throw failure("network");
    }
    if (response.status === 429) {
      throw new ScoreError("rate_limited", retryAfter(response.headers.get("retry-after")));
    }
    if (!response.ok) throw new ScoreError("http");
    if (Number(response.headers.get("content-length") ?? 0) > MAX_RESPONSE_BYTES) {
      throw new ScoreError("invalid");
    }
    try {
      text = await response.text();
    } catch {
      throw failure("network");
    }
  } finally {
    clearTimeout(timer);
  }

  if (text.length > MAX_RESPONSE_BYTES) throw new ScoreError("invalid");
  try {
    return parseVerdict(JSON.parse(text));
  } catch {
    throw new ScoreError("invalid");
  }
}
