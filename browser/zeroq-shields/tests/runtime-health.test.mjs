import assert from "node:assert/strict";
import test from "node:test";

import {
  EXPECTED_RULESET_IDS,
  PACKAGED_STATIC_RULE_COUNT,
  verifyDnrRuntime
} from "../src/runtime-health.js";

function makeApi({
  enabled = EXPECTED_RULESET_IDS,
  capacity = 250000,
  unsupportedId = null,
  disabledByRuleset = {},
  dynamicRuleIds = []
} = {}) {
  const regexChecks = [];
  return {
    regexChecks,
    declarativeNetRequest: {
      GUARANTEED_MINIMUM_STATIC_RULES: 30000,
      async getEnabledRulesets() { return [...enabled]; },
      async getDisabledRuleIds({ rulesetId }) { return [...(disabledByRuleset[rulesetId] || [])]; },
      async getDynamicRules() { return dynamicRuleIds.map((id) => ({ id })); },
      async getAvailableStaticRuleCount() { return capacity; },
      async isRegexSupported(value) {
        regexChecks.push(value);
        const ids = [744738, 744739, 744740, 744801, 744802, 745461];
        return { isSupported: unsupportedId === ids[regexChecks.length - 1] ? false : true };
      }
    }
  };
}

test("verifies all packaged rulesets, capacity and regex compatibility", async () => {
  const api = makeApi();
  const health = await verifyDnrRuntime(api, true);
  assert.equal(health.schema, "zsec.browser-shields.runtime-health.v2");
  assert.equal(health.filteringMode, "full");
  assert.deepEqual(health.enabledRulesets, [...EXPECTED_RULESET_IDS].sort());
  assert.equal(health.packagedStaticRuleCount, PACKAGED_STATIC_RULE_COUNT);
  assert.equal(health.guaranteedMinimumStaticRules, 30000);
  assert.equal(health.regexRulesVerified, 6);
  assert.deepEqual(health.dynamicRuleIds, []);
  assert.deepEqual(health.disabledRuleIds, {
    easylist_ads: [],
    link_cleanup: [],
    privacy_rules: []
  });
  assert.equal(api.regexChecks.length, 6);
});

test("accepts an intentionally disabled protection state with no enabled rulesets", async () => {
  const health = await verifyDnrRuntime(makeApi({ enabled: [] }), false);
  assert.equal(health.filteringMode, "off");
  assert.deepEqual(health.enabledRulesets, []);
});

test("fails closed on incomplete ruleset activation", async () => {
  await assert.rejects(
    verifyDnrRuntime(makeApi({ enabled: ["privacy_rules", "link_cleanup"] }), true),
    /enabled_ruleset_mismatch/
  );
});

test("fails closed when Chromium rejects a packaged regex", async () => {
  await assert.rejects(
    verifyDnrRuntime(makeApi({ unsupportedId: 744801 }), true),
    /regex_rule_744801_unsupported/
  );
});

test("fails closed when Chromium has an individually disabled packaged rule", async () => {
  await assert.rejects(
    verifyDnrRuntime(makeApi({ disabledByRuleset: { easylist_ads: [744733] } }), true),
    /disabled_rules_easylist_ads/
  );
});

test("verifies the exact dynamic-rule identity", async () => {
  const health = await verifyDnrRuntime(makeApi({ dynamicRuleIds: [200001, 100000] }), true, [100000, 200001]);
  assert.deepEqual(health.dynamicRuleIds, [100000, 200001]);
  await assert.rejects(
    verifyDnrRuntime(makeApi({ dynamicRuleIds: [100000] }), true, [100000, 200001]),
    /dynamic_rule_mismatch/
  );
});

test("fails closed on nonsensical static-rule capacity evidence", async () => {
  await assert.rejects(
    verifyDnrRuntime(makeApi({ capacity: -1 }), true),
    /invalid_static_rule_capacity/
  );
});
