import type { StorageArea } from "../src/cache";
import type { Verdict } from "../src/verdict";

export const PHISHING: Verdict = {
  host: "paypa1-login.xyz",
  label: "phishing",
  score: 0.97,
  threshold: 0.42,
  reasons: ["Many hyphens in the host (3)"],
};

/** chrome.storage.session stand-in. */
export function memoryArea(initial: Record<string, unknown> = {}) {
  const data: Record<string, unknown> = { ...initial };
  const area: StorageArea = {
    get: async (key) => (key in data ? { [key]: data[key] } : {}),
    set: async (items) => {
      Object.assign(data, items);
    },
  };
  return { area, data };
}
