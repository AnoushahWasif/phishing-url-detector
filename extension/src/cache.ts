import { CACHE_TTL_MS, MAX_CACHE_ENTRIES } from "./config";
import { parseVerdict, type Verdict } from "./verdict";

/** The two calls used from chrome.storage.session, so tests can pass an in-memory fake. */
export type StorageArea = {
  get(key: string): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
};

type Entry = { at: number; verdict: unknown };
const KEY = "verdicts";

/**
 * Verdicts per host for a few minutes, so reloading a page doesn't call the API again.
 * Session storage lives in memory and is cleared when the browser closes, so no browsing
 * history is written to disk. Two checks racing can drop one entry; that only costs an API call.
 */
export class VerdictCache {
  constructor(
    private readonly area: StorageArea,
    private readonly now: () => number = Date.now,
    private readonly ttlMs = CACHE_TTL_MS,
    private readonly maxEntries = MAX_CACHE_ENTRIES,
  ) {}

  private fresh(entry: unknown, now: number): entry is Entry {
    if (typeof entry !== "object" || entry === null) return false;
    const at = (entry as Entry).at;
    // A clock that went backwards makes the age negative; treat that as stale too.
    return typeof at === "number" && now >= at && now - at < this.ttlMs;
  }

  private async entries(): Promise<Record<string, unknown>> {
    try {
      const stored = (await this.area.get(KEY))[KEY];
      return typeof stored === "object" && stored !== null && !Array.isArray(stored)
        ? (stored as Record<string, unknown>)
        : {};
    } catch {
      return {};
    }
  }

  async get(host: string): Promise<Verdict | null> {
    const entries = await this.entries();
    const entry = Object.hasOwn(entries, host) ? entries[host] : undefined;
    if (!this.fresh(entry, this.now())) return null;
    try {
      return parseVerdict(entry.verdict);
    } catch {
      return null;
    }
  }

  async set(host: string, verdict: Verdict): Promise<void> {
    const now = this.now();
    const others = Object.entries(await this.entries())
      .filter((pair): pair is [string, Entry] => pair[0] !== host && this.fresh(pair[1], now))
      .sort((a, b) => b[1].at - a[1].at)
      .slice(0, this.maxEntries - 1);
    try {
      await this.area.set({ [KEY]: Object.fromEntries([[host, { at: now, verdict }], ...others]) });
    } catch {
      // Storage full or unavailable: carry on uncached.
    }
  }
}
