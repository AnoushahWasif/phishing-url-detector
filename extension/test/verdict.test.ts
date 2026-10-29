import { describe, expect, it } from "vitest";

import { MAX_REASON_LENGTH, MAX_REASONS, parseVerdict, VerdictError } from "../src/verdict";
import { PHISHING } from "./helpers";

describe("parseVerdict", () => {
  it("accepts a real API response", () => {
    expect(parseVerdict(PHISHING)).toEqual(PHISHING);
  });

  it("accepts the allowlist and shortener answers, which have no score", () => {
    for (const label of ["legitimate", "unknown"]) {
      expect(parseVerdict({ ...PHISHING, label, score: null }).score).toBeNull();
    }
  });

  it("drops fields it doesn't know", () => {
    expect(parseVerdict({ ...PHISHING, debug: "x" })).not.toHaveProperty("debug");
  });

  it.each([
    ["null", null],
    ["an array", [PHISHING]],
    ["a string", "phishing"],
    ["an unknown label", { ...PHISHING, label: "malicious" }],
    ["a score above 1", { ...PHISHING, score: 1.5 }],
    ["a negative score", { ...PHISHING, score: -0.1 }],
    ["a score as text", { ...PHISHING, score: "0.9" }],
    ["a NaN score", { ...PHISHING, score: Number.NaN }],
    ["a missing threshold", { ...PHISHING, threshold: undefined }],
    ["an empty host", { ...PHISHING, host: "" }],
    ["a host longer than DNS allows", { ...PHISHING, host: "a".repeat(254) }],
    ["reasons that aren't strings", { ...PHISHING, reasons: [{ html: "<b>x</b>" }] }],
    ["reasons as one string", { ...PHISHING, reasons: "bad" }],
  ])("rejects %s", (_, data) => {
    expect(() => parseVerdict(data)).toThrow(VerdictError);
  });

  it("trims a flood of reasons instead of rejecting the warning", () => {
    const reasons = Array.from({ length: 50 }, () => "x".repeat(5000));
    const verdict = parseVerdict({ ...PHISHING, reasons });
    expect(verdict.label).toBe("phishing");
    expect(verdict.reasons).toHaveLength(MAX_REASONS);
    expect(verdict.reasons.every((r) => r.length === MAX_REASON_LENGTH)).toBe(true);
  });
});
