// Must match host_permissions in public/manifest.json (a test checks this).
export const API_BASE = "http://localhost:8000";
export const TIMEOUT_MS = 5_000;
export const MAX_RESPONSE_BYTES = 16_384;
export const CACHE_TTL_MS = 10 * 60_000;
export const MAX_CACHE_ENTRIES = 500;
export const DEFAULT_BACKOFF_MS = 60_000;
