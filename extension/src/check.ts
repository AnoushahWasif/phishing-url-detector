import type { VerdictCache } from "./cache";
import { ScoreError } from "./client";
import type { CheckReply } from "./messages";
import { checkTarget } from "./target";
import type { Verdict } from "./verdict";

export type Badge = "warn" | "clear" | "skipped" | "unavailable";

export type Deps = {
  extensionId: string;
  score: (target: string) => Promise<Verdict>;
  cache: VerdictCache;
  setBadge: (tabId: number, badge: Badge) => void;
  now: () => number;
  backoff: { until: number };
};

const NONE: CheckReply = { show: false };

/** Answers a content script asking "should this page get a warning?". */
export async function handleCheck(
  sender: chrome.runtime.MessageSender,
  deps: Deps,
): Promise<CheckReply> {
  // Only our own content script in a top-level page. The URL is the one the browser
  // reports for that frame, never something the page itself put in the message.
  const tabId = sender.tab?.id;
  if (sender.id !== deps.extensionId || sender.frameId !== 0 || tabId === undefined || !sender.url) {
    return NONE;
  }
  const target = checkTarget(sender.url);
  if (!target) {
    deps.setBadge(tabId, "skipped");
    return NONE;
  }
  const host = new URL(target).hostname;

  let verdict = await deps.cache.get(host);
  if (!verdict) {
    if (deps.now() < deps.backoff.until) {
      deps.setBadge(tabId, "unavailable");
      return NONE;
    }
    try {
      verdict = await deps.score(target);
    } catch (error) {
      if (error instanceof ScoreError && error.kind === "rate_limited") {
        deps.backoff.until = deps.now() + (error.retryAfterMs ?? 0);
      }
      deps.setBadge(tabId, "unavailable");
      return NONE;
    }
    await deps.cache.set(host, verdict);
  }

  if (verdict.label !== "phishing") {
    deps.setBadge(tabId, "clear");
    return NONE;
  }
  deps.setBadge(tabId, "warn");
  // The host shown is the browser's (punycode for lookalike letters), not the API's echo.
  return { show: true, host, reasons: verdict.reasons };
}
