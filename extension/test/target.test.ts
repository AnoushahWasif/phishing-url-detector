import { describe, expect, it } from "vitest";

import { checkTarget } from "../src/target";

describe("checkTarget", () => {
  it.each([
    ["https://paypa1-login.xyz/signin?session=abc#top", "https://paypa1-login.xyz/"],
    ["http://user:secret@evil.example.com:8443/x", "http://evil.example.com/"],
    ["HTTPS://WWW.Example.COM/Path", "https://www.example.com/"],
    ["https://pаypal.com/", "https://xn--pypal-4ve.com/"], // Cyrillic "а"
    ["http://8.8.8.8/login", "http://8.8.8.8/"],
    ["http://[2001:4860:4860::8888]/", "http://[2001:4860:4860::8888]/"],
    ["https://10.example.com/", "https://10.example.com/"],
    ["https://localhost.evil.com/", "https://localhost.evil.com/"],
  ])("sends only scheme and host for %s", (url, expected) => {
    expect(checkTarget(url)).toBe(expected);
  });

  it.each([
    "chrome://settings",
    "chrome-extension://abc/page.html",
    "file:///C:/Users/me/a.html",
    "about:blank",
    "data:text/html,<h1>x</h1>",
    "javascript:alert(1)",
    "blob:https://example.com/123",
    "ftp://example.com/",
    "not a url",
    "",
  ])("skips non-web page %s", (url) => {
    expect(checkTarget(url)).toBeNull();
  });

  it.each([
    "http://localhost:3000/",
    "http://app.localhost/",
    "http://printer.local/",
    "http://127.0.0.1/",
    "http://0x7f.1/", // the URL parser turns this into 127.0.0.1
    "http://10.1.2.3/",
    "http://172.16.0.1/",
    "http://172.31.255.255/",
    "http://192.168.1.1/admin",
    "http://169.254.169.254/latest/meta-data",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://[fd12:3456::1]/",
    "http://[fe80::1]/",
    "http://intranet/",
  ])("doesn't send local or private address %s", (url) => {
    expect(checkTarget(url)).toBeNull();
  });

  it("checks public addresses just outside the private ranges", () => {
    expect(checkTarget("http://172.32.0.1/")).toBe("http://172.32.0.1/");
    expect(checkTarget("http://11.0.0.1/")).toBe("http://11.0.0.1/");
  });

  it("never sends the scoring API its own address", () => {
    expect(checkTarget("https://api.phish.example/docs", "https://api.phish.example")).toBeNull();
  });
});
