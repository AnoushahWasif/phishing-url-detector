import { showBanner } from "./banner";
import { isWarning } from "./messages";

// Sends no URL: the service worker reads it from the message sender.
chrome.runtime.sendMessage({ type: "check" }).then(
  (reply: unknown) => {
    if (isWarning(reply)) showBanner(document, reply);
  },
  () => {
    // Extension reloaded or worker gone: no banner, nothing else to do.
  },
);
