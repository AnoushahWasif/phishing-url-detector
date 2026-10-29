import { describe, expect, it } from "vitest";

import { type StorageArea, VerdictCache } from "../src/cache";
import { memoryArea, PHISHING } from "./helpers";

function clock(start = 1_000_000) {
  const c = { t: start, now: () => c.t };
  return c;
}

describe("VerdictCache", () => {
  it("returns a stored verdict until it expires", async () => {
    const c = clock();
    const cache = new VerdictCache(memoryArea().area, c.now, 1000);
    await cache.set("evil.example", PHISHING);
    c.t += 999;
    expect(await cache.get("evil.example")).toEqual(PHISHING);
    c.t += 1;
    expect(await cache.get("evil.example")).toBeNull();
  });

  it("misses for a host it hasn't seen", async () => {
    const cache = new VerdictCache(memoryArea().area);
    expect(await cache.get("other.example")).toBeNull();
  });

  it("treats an entry from the future (clock moved back) as stale", async () => {
    const c = clock();
    const cache = new VerdictCache(memoryArea().area, c.now, 1000);
    await cache.set("evil.example", PHISHING);
    c.t -= 5000;
    expect(await cache.get("evil.example")).toBeNull();
  });

  it("keeps only the newest entries when full", async () => {
    const c = clock();
    const { area, data } = memoryArea();
    const cache = new VerdictCache(area, c.now, 60_000, 3);
    for (const host of ["a.example", "b.example", "c.example", "d.example"]) {
      await cache.set(host, { ...PHISHING, host });
      c.t += 1;
    }
    expect(Object.keys(data.verdicts as object).sort()).toEqual(["b.example", "c.example", "d.example"]);
    expect(await cache.get("a.example")).toBeNull();
  });

  it("drops expired entries when writing", async () => {
    const c = clock();
    const { area, data } = memoryArea();
    const cache = new VerdictCache(area, c.now, 1000);
    await cache.set("old.example", PHISHING);
    c.t += 2000;
    await cache.set("new.example", PHISHING);
    expect(Object.keys(data.verdicts as object)).toEqual(["new.example"]);
  });

  it.each([
    ["a string", "garbage"],
    ["an array", [1, 2]],
    ["an entry without a time", { "evil.example": { verdict: PHISHING } }],
    ["a tampered verdict", { "evil.example": { at: 1_000_000, verdict: { ...PHISHING, score: 7 } } }],
  ])("ignores %s in storage", async (_, stored) => {
    const cache = new VerdictCache(memoryArea({ verdicts: stored }).area, clock().now);
    expect(await cache.get("evil.example")).toBeNull();
    await cache.set("ok.example", PHISHING); // and can still write over it
    expect(await cache.get("ok.example")).toEqual(PHISHING);
  });

  it("doesn't treat object built-ins as cached hosts", async () => {
    const cache = new VerdictCache(memoryArea({ verdicts: {} }).area, clock().now);
    expect(await cache.get("constructor")).toBeNull();
    expect(await cache.get("__proto__")).toBeNull();
  });

  it("carries on when storage fails", async () => {
    const broken: StorageArea = {
      get: () => Promise.reject(new Error("quota")),
      set: () => Promise.reject(new Error("quota")),
    };
    const cache = new VerdictCache(broken);
    await expect(cache.set("evil.example", PHISHING)).resolves.toBeUndefined();
    expect(await cache.get("evil.example")).toBeNull();
  });
});
