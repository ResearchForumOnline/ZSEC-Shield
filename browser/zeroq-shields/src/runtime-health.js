export const RUNTIME_HEALTH_SCHEMA = "zsec.browser-shields.runtime-health.v3";

export const EXPECTED_RULESET_IDS = Object.freeze([
  "privacy_rules",
  "link_cleanup",
  "easylist_ads"
]);

export const PACKAGED_STATIC_RULE_COUNT = 49505;
export const RUNTIME_POLICY_REVISION =
  "0.5.2:81d9ba06866a37595397ce62cbc4ccd310c8d9bdc6ed92c9b8b9c89b194ea9d6";

export const REQUIRED_REGEX_RULES = Object.freeze([
  Object.freeze({ id: 744738, regex: "^https?:\\/\\/[0-9a-z]{5,}\\.com\\/.*", isCaseSensitive: false }),
  Object.freeze({ id: 744739, regex: "^https?:\\/\\/[0-9a-z]{8,}\\.xyz\\/.*", isCaseSensitive: false }),
  Object.freeze({ id: 744740, regex: "\\/[0-9a-f]{32}\\/invoke\\.js", isCaseSensitive: false }),
  Object.freeze({ id: 744801, regex: "^https?:\\/\\/www\\.[0-9a-z]{8,}\\.com\\/[0-9a-z]{1,4}\\.js$", isCaseSensitive: false }),
  Object.freeze({ id: 744802, regex: "\\.gsmarena\\.com\\/[0-9]+\\.[a-z]+\\?s?Search=", isCaseSensitive: false }),
  Object.freeze({ id: 745461, regex: "^https?:\\/\\/.*\\/.*sw[0-9._].*", isCaseSensitive: false })
]);

function secureUrl(host, path) {
  return ["https:", "", host, path.replace(/^\/+/, "")].join("/");
}

const REPRESENTATIVE_MATCH_PROBES = Object.freeze([
  Object.freeze({
    name: "zsec_local_privacy",
    rulesetId: "privacy_rules",
    ruleId: 39,
    shouldMatch: true,
    request: Object.freeze({
      url: secureUrl("talktoai.org", "/zero-browser/runtime-check/blocked.js"),
      initiator: secureUrl("talktoai.org", "/"),
      type: "script"
    })
  }),
  Object.freeze({
    name: "link_cleanup",
    rulesetId: "link_cleanup",
    ruleId: 1001,
    shouldMatch: true,
    request: Object.freeze({
      url: secureUrl("example.test", "/?utm_source=zsec-runtime-probe"),
      type: "main_frame"
    })
  }),
  Object.freeze({
    name: "easylist_youtube_pagead",
    rulesetId: "easylist_ads",
    ruleId: 744733,
    shouldMatch: true,
    request: Object.freeze({
      url: secureUrl("www.youtube.com", "/pagead/zsec-runtime-probe"),
      initiator: secureUrl("www.youtube.com", "/watch?v=zsec-runtime-probe"),
      type: "xmlhttprequest"
    })
  }),
  Object.freeze({
    name: "easylist_youtube_ad_break",
    rulesetId: "easylist_ads",
    ruleId: 744734,
    shouldMatch: true,
    request: Object.freeze({
      url: secureUrl("www.youtube.com", "/youtubei/v1/player/ad_break"),
      initiator: secureUrl("www.youtube.com", "/watch?v=zsec-runtime-probe"),
      type: "xmlhttprequest"
    })
  }),
  Object.freeze({
    name: "easylist_youtube_ad_break_control",
    rulesetId: "easylist_ads",
    ruleId: 744734,
    shouldMatch: false,
    request: Object.freeze({
      url: secureUrl("www.youtube.com", "/youtubei/v1/player"),
      initiator: secureUrl("www.youtube.com", "/watch?v=zsec-runtime-probe"),
      type: "xmlhttprequest"
    })
  })
]);

function sameValues(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function canonicalize(value) {
  if (Array.isArray(value)) {
    const normalized = value.map(canonicalize);
    return normalized.every((item) => item === null || ["boolean", "number", "string"].includes(typeof item))
      ? normalized.sort((left, right) => String(left).localeCompare(String(right)))
      : normalized;
  }
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, canonicalize(value[key])])
  );
}

function canonicalRules(rules) {
  return [...rules]
    .map(canonicalize)
    .sort((left, right) => left.id - right.id);
}

function fnv1a32(value) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, "0");
}

export function settingsRevision(settings) {
  const serialized = JSON.stringify({
    protectionEnabled: settings?.protectionEnabled === true,
    highRiskMode: settings?.highRiskMode === true,
    youtubeCleanup: settings?.youtubeCleanup !== false,
    pausedSites: Array.isArray(settings?.pausedSites) ? [...settings.pausedSites] : []
  });
  return `fnv1a32-${fnv1a32(serialized)}-${serialized.length}`;
}

export function storedHealthOrUnchecked(health, extensionVersion, settings) {
  if (health && typeof health === "object" &&
      health.schema === RUNTIME_HEALTH_SCHEMA &&
      health.extensionVersion === extensionVersion &&
      health.policyRevision === RUNTIME_POLICY_REVISION &&
      health.settingsRevision === settingsRevision(settings) &&
      typeof health.ok === "boolean") {
    return health;
  }
  return {
    schema: RUNTIME_HEALTH_SCHEMA,
    extensionVersion,
    policyRevision: RUNTIME_POLICY_REVISION,
    settingsRevision: settingsRevision(settings),
    state: "unchecked",
    ok: false,
    error: "Local filtering has not been verified",
    diagnostic: "health_record_absent_or_stale",
    details: null,
    recordedAt: null
  };
}

async function representativeMatches(dnr, protectionEnabled) {
  if (!protectionEnabled) return { status: "not_applicable", results: [] };
  if (typeof dnr.testMatchOutcome !== "function") {
    return { status: "api_unavailable", results: [] };
  }
  const results = [];
  for (const probe of REPRESENTATIVE_MATCH_PROBES) {
    const outcome = await dnr.testMatchOutcome(probe.request);
    const matched = Array.isArray(outcome?.matchedRules) && outcome.matchedRules.some(
      (rule) => rule.ruleId === probe.ruleId && rule.rulesetId === probe.rulesetId
    );
    if (matched !== probe.shouldMatch) throw new Error(`representative_match_${probe.name}_failed`);
    results.push({
      name: probe.name,
      rulesetId: probe.rulesetId,
      ruleId: probe.ruleId,
      expected: probe.shouldMatch ? "match" : "no_match",
      verified: true
    });
  }
  return { status: "verified", results };
}

export async function verifyDnrRuntime(api, protectionEnabled, expectedDynamicRules = []) {
  if (!api?.declarativeNetRequest) throw new Error("dnr_api_unavailable");
  const dnr = api.declarativeNetRequest;
  const enabledRulesets = [...await dnr.getEnabledRulesets()].sort();
  const expectedRulesets = protectionEnabled ? [...EXPECTED_RULESET_IDS].sort() : [];
  if (!sameValues(enabledRulesets, expectedRulesets)) throw new Error("enabled_ruleset_mismatch");

  const disabledRuleIds = {};
  for (const rulesetId of EXPECTED_RULESET_IDS) {
    const disabled = [...await dnr.getDisabledRuleIds({ rulesetId })].sort((a, b) => a - b);
    if (disabled.length > 0) throw new Error(`disabled_rules_${rulesetId}`);
    disabledRuleIds[rulesetId] = disabled;
  }

  const dynamicRules = canonicalRules(await dnr.getDynamicRules());
  const expectedDynamic = canonicalRules(expectedDynamicRules);
  if (!sameValues(dynamicRules, expectedDynamic)) throw new Error("dynamic_rule_mismatch");

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

  const representative = await representativeMatches(dnr, protectionEnabled);
  return {
    schema: RUNTIME_HEALTH_SCHEMA,
    policyRevision: RUNTIME_POLICY_REVISION,
    filteringMode: protectionEnabled ? "on" : "off",
    enabledRulesets,
    expectedRulesets,
    disabledRuleIds,
    dynamicRuleIds: dynamicRules.map((rule) => rule.id),
    expectedDynamicRuleIds: expectedDynamic.map((rule) => rule.id),
    dynamicRulesVerified: dynamicRules.length,
    packagedStaticRuleCount: PACKAGED_STATIC_RULE_COUNT,
    additionalStaticRuleCapacity: availableStaticRuleCount,
    guaranteedMinimumStaticRules: Number.isSafeInteger(dnr.GUARANTEED_MINIMUM_STATIC_RULES)
      ? dnr.GUARANTEED_MINIMUM_STATIC_RULES
      : 30000,
    regexRulesVerified: regexResults.length,
    regexResults,
    representativeMatchStatus: representative.status,
    representativeMatches: representative.results
  };
}
