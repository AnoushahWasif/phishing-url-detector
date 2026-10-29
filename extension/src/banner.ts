import type { Warning } from "./messages";

const STYLE = `
.box {
  font: 14px/1.4 system-ui, sans-serif;
  color: #fff;
  background: #8e1b1b;
  padding: 12px 16px;
  display: grid;
  gap: 4px;
  box-shadow: 0 2px 8px rgb(0 0 0 / 0.35);
}
strong { font-size: 16px; }
p, ul { margin: 0; }
ul { padding-left: 20px; }
.note { opacity: 0.9; font-size: 13px; }
button {
  justify-self: start;
  margin-top: 4px;
  font: inherit;
  color: #8e1b1b;
  background: #fff;
  border: 0;
  border-radius: 4px;
  padding: 4px 12px;
  cursor: pointer;
}
button:focus-visible { outline: 2px solid #fff; outline-offset: 2px; }
`;

// Inline !important beats any !important rule in the page's own stylesheets.
const HOST_STYLE: Record<string, string> = {
  all: "initial",
  display: "block",
  position: "fixed",
  top: "0",
  left: "0",
  right: "0",
  "z-index": "2147483647",
};

let current: HTMLElement | null = null;

/**
 * The banner lives in a closed shadow root, so page CSS can't restyle it and page
 * scripts can't read or rewrite its contents. Everything from the API goes in as text.
 */
export function buildBanner(doc: Document, warning: Warning) {
  const host = doc.createElement("phishing-url-warning");
  for (const [name, value] of Object.entries(HOST_STYLE)) {
    host.style.setProperty(name, value, "important");
  }
  const root = host.attachShadow({ mode: "closed" });
  const el = <K extends keyof HTMLElementTagNameMap>(tag: K, text?: string) => {
    const node = doc.createElement(tag);
    if (text !== undefined) node.textContent = text;
    return node;
  };

  const box = el("div");
  box.className = "box";
  box.setAttribute("role", "alert");
  box.append(el("strong", "This site may be a phishing page"), el("p", `Site: ${warning.host}`));
  if (warning.reasons.length > 0) {
    const list = el("ul");
    list.append(...warning.reasons.map((reason) => el("li", reason)));
    box.append(list);
  }
  const note = el(
    "p",
    "Judged from the site name only, so it can be wrong. Don't enter passwords or card details unless you're sure this is the real site.",
  );
  note.className = "note";
  const dismiss = el("button", "Dismiss");
  dismiss.type = "button";
  dismiss.addEventListener("click", () => host.remove());
  box.append(note, dismiss);

  root.append(el("style", STYLE), box);
  return { host, root };
}

export function showBanner(doc: Document, warning: Warning): HTMLElement {
  current?.remove();
  const { host } = buildBanner(doc, warning);
  // documentElement, not body: at document_start there is no body yet.
  doc.documentElement.append(host);
  current = host;
  return host;
}
