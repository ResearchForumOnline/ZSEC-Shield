export const DEFAULT_SETTINGS = Object.freeze({
  protectionEnabled: true,
  highRiskMode: false,
  youtubeCleanup: true,
  pausedSites: []
});

const PAUSE_RULE_BASE = 100000;
const PAUSED_RESOURCE_TYPES = Object.freeze([
  "script",
  "image",
  "stylesheet",
  "font",
  "media",
  "xmlhttprequest",
  "ping",
  "websocket",
  "sub_frame",
  "other"
]);

export function normalizeDomain(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim().toLowerCase().replace(/^\.+|\.+$/g, "");
  if (!trimmed || trimmed.length > 253 || trimmed === "localhost") return null;
  if (!/^[a-z0-9.-]+$/.test(trimmed) || trimmed.includes("..")) return null;
  const labels = trimmed.split(".");
  if (labels.length < 2 || labels.some((label) => !label || label.length > 63 || label.startsWith("-") || label.endsWith("-"))) {
    return null;
  }
  return trimmed;
}

export function domainFromUrl(rawUrl) {
  try {
    const url = new URL(rawUrl);
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    return normalizeDomain(url.hostname);
  } catch {
    return null;
  }
}

export function normalizeSettings(value) {
  const source = value && typeof value === "object" ? value : {};
  const pausedSites = Array.isArray(source.pausedSites)
    ? [...new Set(source.pausedSites.map(normalizeDomain).filter(Boolean))].sort()
    : [];
  return {
    protectionEnabled: source.protectionEnabled !== false,
    highRiskMode: source.highRiskMode === true,
    youtubeCleanup: source.youtubeCleanup !== false,
    pausedSites: pausedSites.slice(0, 200)
  };
}

export function buildPauseRules(domains) {
  return domains.map((domain, index) => ({
    id: PAUSE_RULE_BASE + index,
    priority: 100,
    action: { type: "allow" },
    condition: {
      initiatorDomains: [domain],
      resourceTypes: [...PAUSED_RESOURCE_TYPES]
    }
  }));
}

export function pauseRuleIds() {
  return Array.from({ length: 200 }, (_, index) => PAUSE_RULE_BASE + index);
}
