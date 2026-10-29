// @vitest-environment jsdom
import { beforeEach, describe, expect, it } from "vitest";

import { buildBanner, showBanner } from "../src/banner";
import { isWarning } from "../src/messages";

const WARNING = { host: "paypa1-login.xyz", reasons: ["Many hyphens in the host (3)"] };

beforeEach(() => {
  document.documentElement.replaceChildren(document.createElement("head"), document.createElement("body"));
});

describe("banner", () => {
  it("shows the host, the reasons and a dismiss button", () => {
    const { root } = buildBanner(document, WARNING);
    const text = root.textContent ?? "";
    expect(text).toContain("This site may be a phishing page");
    expect(text).toContain("paypa1-login.xyz");
    expect(root.querySelectorAll("li")).toHaveLength(1);
    expect(root.querySelector("[role=alert]")).not.toBeNull();
  });

  it("renders hostile reason text as text, never as HTML", () => {
    const evil = '<img src=x onerror="alert(1)"><script>alert(2)</script>';
    const { root } = buildBanner(document, { host: "<b>x</b>", reasons: [evil] });
    expect(root.querySelector("img")).toBeNull();
    expect(root.querySelector("script")).toBeNull();
    expect(root.querySelector("b")).toBeNull();
    expect(root.querySelector("li")?.textContent).toBe(evil);
  });

  it("leaves out the list when there are no reasons", () => {
    const { root } = buildBanner(document, { ...WARNING, reasons: [] });
    expect(root.querySelector("ul")).toBeNull();
  });

  it("hides its contents from page scripts (closed shadow root)", () => {
    const host = showBanner(document, WARNING);
    expect(host.shadowRoot).toBeNull();
    expect(document.documentElement.textContent).not.toContain("phishing page");
  });

  it("pins itself above the page with !important inline styles", () => {
    const { host } = buildBanner(document, WARNING);
    expect(host.style.getPropertyValue("position")).toBe("fixed");
    expect(host.style.getPropertyPriority("position")).toBe("important");
    expect(host.style.getPropertyValue("z-index")).toBe("2147483647");
  });

  it("goes away when dismissed", () => {
    const { host, root } = buildBanner(document, WARNING);
    document.documentElement.append(host);
    root.querySelector("button")!.click();
    expect(document.querySelector("phishing-url-warning")).toBeNull();
  });

  it("never stacks two banners", () => {
    showBanner(document, WARNING);
    showBanner(document, WARNING);
    expect(document.querySelectorAll("phishing-url-warning")).toHaveLength(1);
  });

  it("is attached before the page has a body", () => {
    document.documentElement.replaceChildren();
    showBanner(document, WARNING);
    expect(document.documentElement.querySelector("phishing-url-warning")).not.toBeNull();
  });
});

describe("isWarning", () => {
  it.each([
    [{ show: true, ...WARNING }, true],
    [{ show: false }, false],
    [{ show: true, host: "x" }, false],
    [{ show: true, host: "x", reasons: [1] }, false],
    [{ show: "yes", ...WARNING }, false],
    [null, false],
    [undefined, false],
  ])("%j -> %s", (reply, expected) => {
    expect(isWarning(reply)).toBe(expected);
  });
});
