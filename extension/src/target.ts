import { API_BASE } from "./config";

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
const PRIVATE_V4 = [
  /^0\./,
  /^10\./,
  /^127\./,
  /^169\.254\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
];

function isLocal(host: string): boolean {
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local")) return true;
  if (host.startsWith("[")) {
    // Loopback, unique-local (fc00::/7) and link-local (fe80::/10) IPv6.
    return host === "[::1]" || /^\[f[cd]/.test(host) || /^\[fe[89ab]/.test(host);
  }
  if (IPV4.test(host)) return PRIVATE_V4.some((range) => range.test(host));
  // A dotless name is an intranet host; the model has never seen one.
  return !host.includes(".");
}

/**
 * What to send to the API for a page, or null if the page shouldn't be checked.
 * The model only reads the host, so only scheme and host leave the browser: no path,
 * query, port or credentials.
 */
export function checkTarget(pageUrl: string, apiBase: string = API_BASE): string | null {
  let url: URL;
  try {
    url = new URL(pageUrl);
  } catch {
    return null;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  // URL already lower-cases, converts to punycode and normalises IPv4 forms like 0x7f.1.
  const host = url.hostname;
  if (!host || isLocal(host) || host === new URL(apiBase).hostname) return null;
  return `${url.protocol}//${host}/`;
}
