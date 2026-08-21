// Local rule construction for the opt-in High-Risk Browsing profile.
// No indicator feed, executable code, telemetry, or remote decision is accepted here.

export const HIGH_RISK_RULE_PRIORITY = 1000;
export const HIGH_RISK_RULE_IDS = Object.freeze([200000, 200001]);
export const HIGH_RISK_ACTIVE_RESOURCE_TYPES = Object.freeze([
  "script",
  "sub_frame",
  "object",
  "websocket"
]);

export function highRiskRuleIds() {
  return [...HIGH_RISK_RULE_IDS];
}

export function buildHighRiskRules(enabled) {
  if (enabled !== true) return [];
  return [
    {
      id: HIGH_RISK_RULE_IDS[0],
      priority: HIGH_RISK_RULE_PRIORITY,
      action: { type: "block" },
      condition: {
        urlFilter: "|http://",
        resourceTypes: ["main_frame"]
      }
    },
    {
      id: HIGH_RISK_RULE_IDS[1],
      priority: HIGH_RISK_RULE_PRIORITY,
      action: { type: "block" },
      condition: {
        domainType: "thirdParty",
        resourceTypes: [...HIGH_RISK_ACTIVE_RESOURCE_TYPES]
      }
    }
  ];
}

export function buildHighRiskRulesForSettings(settings) {
  return buildHighRiskRules(
    settings?.protectionEnabled === true && settings?.highRiskMode === true
  );
}
