export const EXPECTED_RULESET_IDS = Object.freeze([
  "privacy_rules",
  "link_cleanup",
  "easylist_ads"
]);

export const PACKAGED_STATIC_RULE_COUNT = 49505;

const REQUIRED_REGEX_RULES = Object.freeze([
  Object.freeze({ id: 744738, regex: "^https?:\\/\\/[0-9a-z]{5,}\\.com\\/.*", isCaseSensitive: false }),
  Object.freeze({ id: 744739, regex: "^https?:\\/\\/[0-9a-z]{8,}\\.xyz\\/.*", isCaseSensitive: false }),
  Object.freeze({ id: 744740, regex: "\\/[0-9a-f]{32}\\/invoke\\.js", isCaseSensitive: false }),
  Object.freeze({ id: 744801, regex: "^https?:\\/\\/www\\.[0-9a-z]{8,}\\.com\\/[0-9a-z]{1,4}\\.js$", isCaseSensitive: false }),
  Object.freeze({ id: 744802, regex: "\\.gsmarena\\.com\\/[0-9]+\\.[a-z]+\\?s?Search=", isCaseSensitive: false }),
  Object.freeze({ id: 745461, regex: "^https?:\\/\\/.*\\/.*sw[0-9._].*", isCaseSensitive: false })
]);

function sameStrings(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

export async function verifyDnrRuntime(api, protectionEnabled, expectedDynamicRuleIds = []) {
  if (!api?.declarativeNetRequest) throw new Error("dnr_api_unavailable");
  const dnr = api.declarativeNetRequest;
  const enabledRulesets = [...await dnr.getEnabledRulesets()].sort();
  const expectedRulesets = protectionEnabled ? [...EXPECTED_RULESET_IDS].sort() : [];
  if (!sameStrings(enabledRulesets, expectedRulesets)) {
    throw new Error("enabled_ruleset_mismatch");
  }

  const disabledRuleIds = {};
  for (const rulesetId of EXPECTED_RULESET_IDS) {
    const disabled = [...await dnr.getDisabledRuleIds({ rulesetId })].sort((a, b) => a - b);
    if (disabled.length > 0) throw new Error(`disabled_rules_${rulesetId}`);
    disabledRuleIds[rulesetId] = disabled;
  }

  const dynamicRuleIds = (await dnr.getDynamicRules())
    .map((rule) => rule.id)
    .sort((a, b) => a - b);
  const expectedDynamic = [...expectedDynamicRuleIds].sort((a, b) => a - b);
  if (!sameStrings(dynamicRuleIds, expectedDynamic)) throw new Error("dynamic_rule_mismatch");

  const availableStaticRuleCount = await dnr.getAvailableStaticRuleCount();
  if (!Number.isSafeInteger(availableStaticRuleCount) || availableStaticRuleCount < 0) {
    throw new Error("invalid_static_rule_capacity");
  }

  const regexResults = [];
  for (const rule of REQUIRED_REGEX_RULES) {
    const result = await dnr.isRegexSupported({
      regex: rule.regex,
      isCaseSensitive: rule.isCaseSensitive
    });
    if (result?.isSupported !== true) throw new Error(`regex_rule_${rule.id}_unsupported`);
    regexResults.push({ id: rule.id, isSupported: true });
  }

  return {
    schema: "zsec.browser-shields.runtime-health.v2",
    filteringMode: protectionEnabled ? "full" : "off",
    enabledRulesets,
    expectedRulesets,
    disabledRuleIds,
    dynamicRuleIds,
    expectedDynamicRuleIds: expectedDynamic,
    packagedStaticRuleCount: PACKAGED_STATIC_RULE_COUNT,
    availableStaticRuleCount,
    guaranteedMinimumStaticRules: Number.isSafeInteger(dnr.GUARANTEED_MINIMUM_STATIC_RULES)
      ? dnr.GUARANTEED_MINIMUM_STATIC_RULES
      : 30000,
    regexRulesVerified: regexResults.length,
    regexResults
  };
}
