import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { API_BASE } from "../src/config";

const manifest = JSON.parse(readFileSync(new URL("../public/manifest.json", import.meta.url), "utf8"));

describe("manifest", () => {
  it("is Manifest V3", () => {
    expect(manifest.manifest_version).toBe(3);
  });

  it("asks only for storage", () => {
    expect(manifest.permissions).toEqual(["storage"]);
    expect(manifest.optional_permissions).toBeUndefined();
  });

  it("has host access to the scoring API and nothing else", () => {
    const api = new URL(API_BASE);
    expect(manifest.host_permissions).toContain(`${api.origin}/*`);
    for (const pattern of manifest.host_permissions as string[]) {
      expect(pattern).not.toMatch(/^\*|<all_urls>|\/\/\*\.?/);
      expect(new URL(pattern.replace("/*", "/")).port).toBe(api.port);
    }
  });

  it("runs the content script in top-level http(s) pages only", () => {
    const [script, ...rest] = manifest.content_scripts;
    expect(rest).toEqual([]);
    expect(script.matches).toEqual(["http://*/*", "https://*/*"]);
    expect(script.all_frames).toBe(false);
  });

  it("doesn't loosen the default extension CSP or expose anything to pages", () => {
    expect(manifest.content_security_policy).toBeUndefined();
    expect(manifest.web_accessible_resources).toBeUndefined();
    expect(manifest.externally_connectable).toBeUndefined();
  });

  it("has the same version as package.json", () => {
    const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
    expect(manifest.version).toBe(pkg.version);
  });
});
