import { describe, expect, it, vi } from "vitest";

import { VerdictCache } from "../src/cache";
import { type Badge, type Deps, handleCheck } from "../src/check";
import { ScoreError } from "../src/client";
import type { Verdict } from "../src/verdict";
import { memoryArea, PHISHING } from "./helpers";

const ID = "abcdefghijklmnopabcdefghijklmnop";
const LEGIT: Verdict = { ...PHISHING, label: "legitimate", score: 0.03, reasons: [] };

function setup(score: Deps["score"] = async () => PHISHING) {
  const badges: [number, Badge][] = [];
  const clock = { t: 1_000_000 };
  const deps: Deps = {
    extensionId: ID,
    score: vi.fn(score),
    cache: new VerdictCache(memoryArea().area, () => clock.t),
    setBadge: (tabId, badge) => badges.push([tabId, badge]),
    now: () => clock.t,
    backoff: { until: 0 },
  };
  return { deps, badges, clock };
}

function sender(url: string, extra: Partial<chrome.runtime.MessageSender> = {}): chrome.runtime.MessageSender {
  return { id: ID, frameId: 0, url, tab: { id: 7 } as chrome.tabs.Tab, ...extra };
}

describe("handleCheck", () => {
  it("warns and sets the badge for a phishing verdict", async () => {
    const { deps, badges } = setup();
    const reply = await handleCheck(sender("https://paypa1-login.xyz/signin?token=s3cret"), deps);
    expect(reply).toEqual({ show: true, host: "paypa1-login.xyz", reasons: PHISHING.reasons });
    expect(badges).toEqual([[7, "warn"]]);
    // Only scheme and host went to the API.
    expect(deps.score).toHaveBeenCalledWith("https://paypa1-login.xyz/");
  });

  it("stays quiet for legitimate and unknown verdicts", async () => {
    for (const verdict of [LEGIT, { ...LEGIT, label: "unknown" as const, score: null }]) {
      const { deps, badges } = setup(async () => verdict);
      expect(await handleCheck(sender("https://example.com/"), deps)).toEqual({ show: false });
      expect(badges).toEqual([[7, "clear"]]);
    }
  });

  it("shows the browser's host, not whatever host the API echoes", async () => {
    const { deps } = setup(async () => ({ ...PHISHING, host: "trusted-bank.com" }));
    const reply = await handleCheck(sender("https://paypa1-login.xyz/"), deps);
    expect(reply).toMatchObject({ host: "paypa1-login.xyz" });
  });

  it.each([
    ["another extension", { id: "someone-else" }],
    ["an iframe", { frameId: 3 }],
    ["a sender without a tab", { tab: undefined }],
    ["a sender without a URL", { url: undefined }],
  ])("ignores %s", async (_, extra) => {
    const { deps, badges } = setup();
    expect(await handleCheck(sender("https://paypa1-login.xyz/", extra), deps)).toEqual({ show: false });
    expect(deps.score).not.toHaveBeenCalled();
    expect(badges).toEqual([]);
  });

  it("doesn't send private addresses to the API", async () => {
    const { deps, badges } = setup();
    await handleCheck(sender("http://192.168.1.1/admin"), deps);
    expect(deps.score).not.toHaveBeenCalled();
    expect(badges).toEqual([[7, "skipped"]]);
  });

  it("answers repeat visits from the cache", async () => {
    const { deps } = setup();
    await handleCheck(sender("https://paypa1-login.xyz/a"), deps);
    const reply = await handleCheck(sender("https://paypa1-login.xyz/b"), deps);
    expect(reply.show).toBe(true);
    expect(deps.score).toHaveBeenCalledTimes(1);
  });

  it("shows no banner and a '?' badge when the API is down, and doesn't cache the failure", async () => {
    const { deps, badges } = setup(async () => {
      throw new ScoreError("network");
    });
    expect(await handleCheck(sender("https://paypa1-login.xyz/"), deps)).toEqual({ show: false });
    expect(badges).toEqual([[7, "unavailable"]]);
    await handleCheck(sender("https://paypa1-login.xyz/"), deps);
    expect(deps.score).toHaveBeenCalledTimes(2);
  });

  it("stops calling the API after a 429 until Retry-After has passed", async () => {
    const { deps, clock } = setup(async () => {
      throw new ScoreError("rate_limited", 30_000);
    });
    await handleCheck(sender("https://a-site.example/"), deps);
    await handleCheck(sender("https://b-site.example/"), deps);
    expect(deps.score).toHaveBeenCalledTimes(1);

    clock.t += 30_000;
    await handleCheck(sender("https://c-site.example/"), deps);
    expect(deps.score).toHaveBeenCalledTimes(2);
  });

  it("still answers from the cache during a backoff", async () => {
    const { deps } = setup();
    await handleCheck(sender("https://paypa1-login.xyz/"), deps);
    deps.backoff.until = Number.POSITIVE_INFINITY;
    expect((await handleCheck(sender("https://paypa1-login.xyz/"), deps)).show).toBe(true);
  });
});
