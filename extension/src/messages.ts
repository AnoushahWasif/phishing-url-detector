export type CheckRequest = { type: "check" };
export type Warning = { host: string; reasons: string[] };
export type CheckReply = { show: false } | ({ show: true } & Warning);

export function isCheckRequest(message: unknown): message is CheckRequest {
  return typeof message === "object" && message !== null && (message as CheckRequest).type === "check";
}

export function isWarning(reply: unknown): reply is { show: true } & Warning {
  if (typeof reply !== "object" || reply === null) return false;
  const r = reply as Record<string, unknown>;
  return (
    r.show === true &&
    typeof r.host === "string" &&
    Array.isArray(r.reasons) &&
    r.reasons.every((reason) => typeof reason === "string")
  );
}
