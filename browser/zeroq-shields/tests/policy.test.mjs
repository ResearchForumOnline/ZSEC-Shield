import assert from "node:assert/strict";
import test from "node:test";

import {
  buildPauseRules,
  domainFromUrl,
  normalizeDomain,
  normalizeSettings,
  pauseRuleIds
} from "../src/policy.js";

test("domains and URLs are normalized without accepting privileged schemes", () => {
  assert.equal(normalizeDomain(" Example.COM. "), "example.com");
  assert.equal(domainFromUrl("https://sub.example.com/path?q=1"), "sub.example.com");
  assert.equal(domainFromUrl("chrome://settings"), null);
  assert.equal(normalizeDomain("bad..example.com"), null);
});

test("settings reject malformed domains and deduplicate pauses", () => {
  const settings = normalizeSettings({
    protectionEnabled: false,
    highRiskMode: true,
    youtubeCleanup: true,
    pausedSites: ["B.example", "b.example", "invalid", "a.example"]
  });
  assert.deepEqual(settings, {
    protectionEnabled: false,
    highRiskMode: true,
    youtubeCleanup: true,
    pausedSites: ["a.example", "b.example"]
  });
});

test("high-risk mode defaults off", () => {
  assert.equal(normalizeSettings({}).highRiskMode, false);
});

test("pause rules are bounded, deterministic allow rules", () => {
  const rules = buildPauseRules(["a.example", "b.example"]);
  assert.equal(rules.length, 2);
  assert.equal(rules[0].id, 100000);
  assert.equal(rules[0].priority, 100);
  assert.equal(rules[0].action.type, "allow");
  assert.deepEqual(rules[0].condition.initiatorDomains, ["a.example"]);
  assert.equal(pauseRuleIds().length, 200);
});
