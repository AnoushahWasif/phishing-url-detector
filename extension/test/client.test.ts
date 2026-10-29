import { afterEach, describe, expect, it, vi } from "vitest";

import { ScoreError, scoreUrl } from "../src/client";
import { DEFAULT_BACKOFF_MS, MAX_RESPONSE_BYTES, TIMEOUT_MS } from "../src/config";
import { PHISHING } from "./helpers";

const BASE = "https://api.phish.example";
const TARGET = "https://paypa1-login.xyz/";

function respond(body: unknown, init: ResponseInit = {}) {
  const text = typeof body === "string" ? body : JSON.stringify(body);
  return vi.fn<typeof fetch>().mockResolvedValue(new Response(text, { status: 200, ...init }));
}

async function failure(promise: Promise<unknown>): Promise<ScoreError> {
  const error = await promise.catch((e: unknown) => e);
  expect(error).toBeInstanceOf(ScoreError);
  return error as ScoreError;
}

afterEach(() => {
  vi.useRealTimers();
});

describe("scoreUrl", () => {
  it("posts only the target and returns the parsed verdict", async () => {
    const fetchImpl = respond(PHISHING);
    expect(await scoreUrl(TARGET, { base: BASE, fetchImpl })).toEqual(PHISHING);
    const [url, init] = fetchImpl.mock.calls[0]!;
    expect(url).toBe(`${BASE}/score`);
    expect(JSON.parse(init?.body as string)).toEqual({ url: TARGET });
    expect(init).toMatchObject({ method: "POST", credentials: "omit", redirect: "error", cache: "no-store" });
  });

  it.each([500, 404, 422])("turns HTTP %i into an http error", async (status) => {
    const error = await failure(scoreUrl(TARGET, { base: BASE, fetchImpl: respond("{}", { status }) }));
    expect(error.kind).toBe("http");
  });

  it.each([
    ["30", 30_000],
    ["99999", 600_000],
    ["-5", DEFAULT_BACKOFF_MS],
    ["soon", DEFAULT_BACKOFF_MS],
  ])("reads Retry-After %s as a capped backoff", async (header, expected) => {
    const fetchImpl = respond("{}", { status: 429, headers: { "retry-after": header } });
    const error = await failure(scoreUrl(TARGET, { base: BASE, fetchImpl }));
    expect(error.kind).toBe("rate_limited");
    expect(error.retryAfterMs).toBe(expected);
  });

  it("uses the default backoff when a 429 has no Retry-After", async () => {
    const error = await failure(scoreUrl(TARGET, { base: BASE, fetchImpl: respond("{}", { status: 429 }) }));
    expect(error.retryAfterMs).toBe(DEFAULT_BACKOFF_MS);
  });

  it.each([
    ["not JSON", "<html>502 Bad Gateway</html>"],
    ["the wrong shape", { verdict: "phishing" }],
    ["a body over the size cap", "x".repeat(MAX_RESPONSE_BYTES + 1)],
  ])("rejects %s", async (_, body) => {
    const error = await failure(scoreUrl(TARGET, { base: BASE, fetchImpl: respond(body) }));
    expect(error.kind).toBe("invalid");
  });

  it("rejects a declared oversized body before reading it", async () => {
    const fetchImpl = respond(PHISHING, { headers: { "content-length": String(MAX_RESPONSE_BYTES + 1) } });
    expect((await failure(scoreUrl(TARGET, { base: BASE, fetchImpl }))).kind).toBe("invalid");
  });

  it("reports a network failure (API not running)", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockRejectedValue(new TypeError("Failed to fetch"));
    expect((await failure(scoreUrl(TARGET, { base: BASE, fetchImpl }))).kind).toBe("network");
  });

  it("times out an API that never answers", async () => {
    vi.useFakeTimers();
    const fetchImpl = vi.fn<typeof fetch>(
      (_url, init) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
        }),
    );
    const pending = failure(scoreUrl(TARGET, { base: BASE, fetchImpl }));
    await vi.advanceTimersByTimeAsync(TIMEOUT_MS + 1);
    expect((await pending).kind).toBe("timeout");
  });

  it("times out an API that sends headers and then stalls the body", async () => {
    vi.useFakeTimers();
    const fetchImpl = vi.fn<typeof fetch>((_url, init) => {
      const body = new ReadableStream({
        start(controller) {
          init?.signal?.addEventListener("abort", () => controller.error(new DOMException("aborted", "AbortError")));
        },
      });
      return Promise.resolve(new Response(body, { status: 200 }));
    });
    const pending = failure(scoreUrl(TARGET, { base: BASE, fetchImpl }));
    await vi.advanceTimersByTimeAsync(TIMEOUT_MS + 1);
    expect((await pending).kind).toBe("timeout");
  });
});
