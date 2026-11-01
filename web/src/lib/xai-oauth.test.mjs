import { safeXAIAuthURL } from "./xai-oauth.ts";
import assert from "node:assert/strict";
import test from "node:test";

test("Grok login accepts official HTTPS verification URLs with an optional code", () => {
  for (const url of ["https://auth.x.ai/device", "https://accounts.x.ai/device?user_code=TEST-CODE"]) {
    assert.equal(safeXAIAuthURL(url), url);
  }
});

test("Grok login rejects off-origin, credential-bearing and pseudo-scheme URLs", () => {
  for (const url of [
    undefined,
    "",
    "javascript:alert(1)",
    "http://auth.x.ai/device",
    "https://auth.x.ai.evil.example/device",
    "https://evil.example/?next=https://auth.x.ai",
    "https://auth.x.ai@evil.example/device",
    "https://user:pass@auth.x.ai/device",
    "https://auth.x.ai:8443/device",
    "//auth.x.ai/device",
    "/device",
    "https://auth.\nx.ai/device",
  ]) {
    assert.equal(safeXAIAuthURL(url), undefined, String(url));
  }
});
