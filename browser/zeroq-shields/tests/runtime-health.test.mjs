import assert from "node:assert/strict";
import test from "node:test";

import {
  EXPECTED_RULESET_IDS,
  PACKAGED_STATIC_RULE_COUNT,
  RUNTIME_HEALTH_SCHEMA,
  RUNTIME_POLICY_REVISION,
  settingsRevision,
  storedHealthOrUnchecked,
  verifyDnrRuntime
} from "../src/runtime-health.js";

const PAUSE_RULE = {
  id: 100000,
  priority: 100,
  action: { type: "allow" },
  condition: {
    initiatorDomains: ["example.com"],
    resourceTypes: ["script", "image"]
  }
};

function makeApi({
  enabled = EXPECTED_RULESET_IDS,
  capacity = 250000,
  unsupportedId = null,
  disabledByRuleset = {},
  dynamicRules = [],
  representative = "supported",
  failedRepresentative = null
} = {}) {
  const regexChecks = [];
  const matchChecks = [];
  const dnr = {
    GUARANTEED_MINIMUM_STATIC_RULES: 30000,
    async getEnabledRulesets() { return [...enabled]; },
    async getDisabledRuleIds({ rulesetId }) { return [...(disabledByRuleset[rulesetId] || [])]; },
    async getDynamicRules() { return structuredClone(dynamicRules); },
    async getAvailableStaticRuleCount() { return capacity; },
    async isRegexSupported(value) {
      regexChecks.push(value);
      const ids = [744738, 744739, 744740, 744801, 744802, 745461];
      return { isSupported: unsupportedId !== ids[regexChecks.length - 1] };
    }
  };
  if (representative === "supported") {
    dnr.testMatchOutcome = async (request) => {
      matchChecks.push(request);
      const url = request.url;
      const matches = [];
      if (url.includes("/runtime-check/blocked.js")) matches.push({ rulesetId: "privacy_rules", ruleId: 39 });
      if (url.includes("utm_source=")) matches.push({ rulesetId: "link_cleanup", ruleId: 1001 });
      if (url.includes("/pagead/")) matches.push({ rulesetId: "easylist_ads", ruleId: 744733 });
      if (url.endsWith("/ad_break")) matches.push({ rulesetId: "easylist_ads", ruleId: 744734 });
      return {
        matchedRules: matches.filter((rule) =>
          failedRepresentative !== `${rule.rulesetId}:${rule.ruleId}`
        )
      };
    };
  }
  return { regexChecks, matchChecks, declarativeNetRequest: dnr };
}

test("verifies exact packaged rulesets, dynamic rules, regexes and representative matches", async () => {
  const api = makeApi({ dynamicRules: [PAUSE_RULE] });
  const health = await verifyDnrRuntime(api, true, [PAUSE_RULE]);
  assert.equal(health.schema, RUNTIME_HEALTH_SCHEMA);
  assert.equal(health.policyRevision, RUNTIME_POLICY_REVISION);
  assert.equal(health.filteringMode, "on");
  assert.deepEqual(health.enabledRulesets, [...EXPECTED_RULESET_IDS].sort());
  assert.equal(health.packagedStaticRuleCount, PACKAGED_STATIC_RULE_COUNT);
  assert.equal(health.guaranteedMinimumStaticRules, 30000);
  assert.equal(health.additionalStaticRuleCapacity, 250000);
  assert.equal(health.regexRulesVerified, 6);
  assert.equal(health.dynamicRulesVerified, 1);
  assert.deepEqual(health.dynamicRuleIds, [100000]);
  assert.equal(health.representativeMatchStatus, "verified");
  assert.equal(health.representativeMatches.length, 5);
  assert.equal(api.regexChecks.length, 6);
  assert.equal(api.matchChecks.length, 5);
});

test("accepts an intentionally disabled state and does not run representative probes", async () => {
  const api = makeApi({ enabled: [] });
  const health = await verifyDnrRuntime(api, false, []);
  assert.equal(health.filteringMode, "off");
  assert.deepEqual(health.enabledRulesets, []);
  assert.equal(health.representativeMatchStatus, "not_applicable");
  assert.equal(api.matchChecks.length, 0);
});

test("records a limited verification state when the unpacked-only match API is absent", async () => {
  const health = await verifyDnrRuntime(
    makeApi({ representative: "unavailable" }),
    true,
    []
  );
  assert.equal(health.representativeMatchStatus, "api_unavailable");
  assert.deepEqual(health.representativeMatches, []);
});

test("fails closed on ruleset, disabled-rule, regex and capacity mismatches", async () => {
  await assert.rejects(
    verifyDnrRuntime(makeApi({ enabled: ["privacy_rules", "link_cleanup"] }), true),
    /enabled_ruleset_mismatch/
  );
  await assert.rejects(
    verifyDnrRuntime(makeApi({ disabledByRuleset: { easylist_ads: [744733] } }), true),
    /disabled_rules_easylist_ads/
  );
  await assert.rejects(
    verifyDnrRuntime(makeApi({ unsupportedId: 744801 }), true),
    /regex_rule_744801_unsupported/
  );
  await assert.rejects(
    verifyDnrRuntime(makeApi({ capacity: -1 }), true),
    /invalid_static_rule_capacity/
  );
});

test("fails closed when a dynamic rule keeps the expected ID but changes behavior", async () => {
  const altered = structuredClone(PAUSE_RULE);
  altered.action = { type: "block" };
  await assert.rejects(
    verifyDnrRuntime(makeApi({ dynamicRules: [altered] }), true, [PAUSE_RULE]),
    /dynamic_rule_mismatch/
  );
});

test("normalizes semantically unordered dynamic rule arrays before comparison", async () => {
  const returned = structuredClone(PAUSE_RULE);
  returned.condition.resourceTypes.reverse();
  const health = await verifyDnrRuntime(
    makeApi({ dynamicRules: [returned] }),
    true,
    [PAUSE_RULE]
  );
  assert.deepEqual(health.dynamicRuleIds, [100000]);
});

test("fails closed when a required representative EasyList match is absent", async () => {
  await assert.rejects(
    verifyDnrRuntime(
      makeApi({ failedRepresentative: "easylist_ads:744734" }),
      true,
      []
    ),
    /representative_match_easylist_youtube_ad_break_failed/
  );
});

test("missing, wrong-version, wrong-policy and wrong-settings health is unchecked", () => {
  const settings = {
    protectionEnabled: true,
    highRiskMode: false,
    youtubeCleanup: true,
    pausedSites: []
  };
  const valid = {
    schema: RUNTIME_HEALTH_SCHEMA,
    extensionVersion: "0.5.2",
    policyRevision: RUNTIME_POLICY_REVISION,
    settingsRevision: settingsRevision(settings),
    ok: true,
    state: "verified"
  };
  assert.equal(storedHealthOrUnchecked(valid, "0.5.2", settings), valid);
  for (const candidate of [
    null,
    { ...valid, extensionVersion: "0.5.1" },
    { ...valid, policyRevision: "stale" },
    { ...valid, settingsRevision: "stale" }
  ]) {
    const health = storedHealthOrUnchecked(candidate, "0.5.2", settings);
    assert.equal(health.ok, false);
    assert.equal(health.state, "unchecked");
    assert.equal(health.diagnostic, "health_record_absent_or_stale");
  }
});
