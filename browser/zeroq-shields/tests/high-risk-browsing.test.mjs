import assert from "node:assert/strict";
import test from "node:test";

import {
  HIGH_RISK_ACTIVE_RESOURCE_TYPES,
  HIGH_RISK_RULE_PRIORITY,
  buildHighRiskRules,
  buildHighRiskRulesForSettings,
  highRiskRuleIds
} from "../src/high-risk-browsing.js";

test("high-risk rules are opt-in and bounded", () => {
  assert.deepEqual(buildHighRiskRules(false), []);
  assert.deepEqual(buildHighRiskRules(undefined), []);
  assert.deepEqual(highRiskRuleIds(), [200000, 200001]);
  assert.equal(buildHighRiskRules(true).length, 2);
});

test("high-risk mode blocks plaintext navigation and third-party active delivery", () => {
  const [plaintext, thirdParty] = buildHighRiskRules(true);
  assert.equal(plaintext.priority, HIGH_RISK_RULE_PRIORITY);
  assert.equal(plaintext.action.type, "block");
  assert.equal(plaintext.condition.urlFilter, "|http://");
  assert.deepEqual(plaintext.condition.resourceTypes, ["main_frame"]);

  assert.equal(thirdParty.priority, HIGH_RISK_RULE_PRIORITY);
  assert.equal(thirdParty.action.type, "block");
  assert.equal(thirdParty.condition.domainType, "thirdParty");
  assert.deepEqual(thirdParty.condition.resourceTypes, [
    "script",
    "sub_frame",
    "object",
    "websocket"
  ]);
  assert.deepEqual([...HIGH_RISK_ACTIVE_RESOURCE_TYPES], thirdParty.condition.resourceTypes);
});

test("high-risk rule priority exceeds the site-pause allow priority", () => {
  assert.ok(HIGH_RISK_RULE_PRIORITY > 100);
});

test("the master protection switch gates the high-risk preference", () => {
  assert.equal(
    buildHighRiskRulesForSettings({ protectionEnabled: false, highRiskMode: true }).length,
    0
  );
  assert.equal(
    buildHighRiskRulesForSettings({ protectionEnabled: true, highRiskMode: false }).length,
    0
  );
  assert.equal(
    buildHighRiskRulesForSettings({ protectionEnabled: true, highRiskMode: true }).length,
    2
  );
});
