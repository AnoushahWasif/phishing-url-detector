import { VerdictCache } from "./cache";
import { type Badge, handleCheck } from "./check";
import { scoreUrl } from "./client";
import { isCheckRequest } from "./messages";

const BADGES: Record<Badge, { text: string; color: string; title: string }> = {
  warn: { text: "!", color: "#c62828", title: "Warning: this site may be a phishing page" },
  clear: { text: "", color: "#000000", title: "Phishing URL warning: nothing flagged" },
  skipped: { text: "", color: "#000000", title: "Not checked: local or private address" },
  unavailable: { text: "?", color: "#757575", title: "Check unavailable: scoring API not reachable" },
};

function setBadge(tabId: number, badge: Badge) {
  const { text, color, title } = BADGES[badge];
  const ignoreClosedTab = () => {};
  chrome.action.setBadgeText({ tabId, text }).catch(ignoreClosedTab);
  chrome.action.setBadgeBackgroundColor({ tabId, color }).catch(ignoreClosedTab);
  chrome.action.setTitle({ tabId, title }).catch(ignoreClosedTab);
}

const deps = {
  extensionId: chrome.runtime.id,
  score: (target: string) => scoreUrl(target),
  cache: new VerdictCache(chrome.storage.session),
  setBadge,
  now: Date.now,
  // In memory: if the worker is shut down the backoff resets, which costs at most one 429.
  backoff: { until: 0 },
};

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!isCheckRequest(message)) return false;
  handleCheck(sender, deps).then(sendResponse, () => sendResponse({ show: false }));
  return true; // keep the channel open for the async reply
});
