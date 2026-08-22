import assert from "node:assert/strict";
import test from "node:test";

import {
  UNCHECKED_HEALTH,
  healthPresentation,
  normalizeContextDomain
} from "../src/popup-state.js";

const settings = {
  protectionEnabled: true,
  highRiskMode: false,
  youtubeCleanup: true,
  pausedSites: []
};

test("popup defaults to unavailable until health is explicitly verified", () => {
  const view = healthPresentation(settings);
  assert.equal(UNCHECKED_HEALTH.ok, false);
  assert.equal(view.unavailable, true);
  assert.match(view.status, /Verifying/);
  assert.match(view.message, /not been verified/);
});

test("popup distinguishes full representative evidence from limited verification", () => {
  const full = healthPresentation(settings, {
    ok: true,
    state: "verified",
    details: {
      filteringMode: "on",
      packagedStaticRuleCount: 49505,
      regexRulesVerified: 6,
      representativeMatchStatus: "verified",
      representativeMatches: [{}, {}, {}, {}, {}]
    }
  });
  assert.equal(full.status, "ZSEC rules are verified");
  assert.match(full.coverage, /49,505 packaged rules/);
  assert.match(full.coverage, /5 representative checks passed/);

  const limited = healthPresentation(settings, {
    ok: true,
    state: "verified_limited",
    details: {
      filteringMode: "on",
      packagedStaticRuleCount: 49505,
      regexRulesVerified: 6,
      representativeMatchStatus: "api_unavailable",
      representativeMatches: []
    }
  });
  assert.match(limited.status, /limited verification/);
  assert.match(limited.coverage, /representative checks unavailable/);
});

test("popup reports intentional protection-off state without calling it unavailable", () => {
  const view = healthPresentation(
    { ...settings, protectionEnabled: false },
    {
      ok: true,
      state: "disabled_by_user",
      details: {
        filteringMode: "off",
        packagedStaticRuleCount: 49505,
        regexRulesVerified: 6,
        representativeMatchStatus: "not_applicable",
        representativeMatches: []
      }
    }
  );
  assert.equal(view.unavailable, false);
  assert.equal(view.status, "ZSEC rules are off");
  assert.equal(view.coverage, "Network filtering is intentionally off");
});

test("native settings context accepts only normalized DNS-style domains", () => {
  assert.equal(normalizeContextDomain("WWW.YouTube.com."), "www.youtube.com");
  for (const value of [null, "", "localhost", "youtube", "youtube..com", "-bad.example", "bad-.example", "youtube.com/path", "https://youtube.com"]) {
    assert.equal(normalizeContextDomain(value), null);
  }
});
