// Bundled compatibility policy for functional login/site resources. These rules
// override ad-list false positives only; High-Risk Browsing and the native
// browser's threat decisions retain their higher-priority protections.
export const LOGIN_COMPATIBILITY_PRIORITY = 60;
const RULE_BASE = 210000;
const RESOURCE_TYPES = Object.freeze([
  "script", "image", "stylesheet", "font", "xmlhttprequest",
  "websocket", "sub_frame", "media", "other"
]);
const EXCLUDED_INITIATORS = Object.freeze(["youtube.com", "youtube-nocookie.com"]);

export const LOGIN_COMPATIBILITY_GROUPS = Object.freeze([
  Object.freeze({
    name: "Google",
    sites: ["google.com"],
    hosts: ["google.com", "www.google.com", "accounts.google.com", "mail.google.com", "drive.google.com", "docs.google.com", "gemini.google.com", "myaccount.google.com", "apis.google.com", "www.googleapis.com", "oauth2.googleapis.com", "accounts.gstatic.com", "www.gstatic.com", "ssl.gstatic.com", "fonts.gstatic.com", "fonts.googleapis.com", "lh3.googleusercontent.com"],
    cdnDomains: []
  }),
  Object.freeze({
    name: "ChatGPT / OpenAI",
    sites: ["chatgpt.com", "openai.com", "chat.openai.com"],
    hosts: ["chatgpt.com", "www.chatgpt.com", "chat.openai.com", "openai.com", "www.openai.com", "auth.openai.com", "auth0.openai.com", "platform.openai.com", "cdn.oaistatic.com", "challenges.cloudflare.com", "accounts.google.com", "appleid.apple.com", "login.live.com", "login.microsoftonline.com"],
    cdnDomains: ["oaistatic.com", "oaiusercontent.com"]
  }),
  Object.freeze({
    name: "Facebook / Instagram",
    sites: ["facebook.com", "instagram.com", "messenger.com"],
    hosts: ["facebook.com", "www.facebook.com", "m.facebook.com", "web.facebook.com", "www.messenger.com", "messenger.com", "instagram.com", "www.instagram.com", "graph.facebook.com", "connect.facebook.net"],
    cdnDomains: ["fbcdn.net", "cdninstagram.com"]
  }),
  Object.freeze({
    name: "Microsoft",
    sites: ["microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com"],
    hosts: ["www.microsoft.com", "account.microsoft.com", "login.microsoftonline.com", "login.live.com", "account.live.com", "outlook.live.com", "outlook.office.com", "www.office.com", "office.com", "aadcdn.msauth.net", "aadcdn.msftauth.net", "logincdn.msauth.net"],
    cdnDomains: []
  }),
  Object.freeze({
    name: "GitHub",
    sites: ["github.com"],
    hosts: ["github.com", "www.github.com", "api.github.com", "github.githubassets.com", "avatars.githubusercontent.com", "challenges.cloudflare.com"],
    cdnDomains: []
  }),
  Object.freeze({
    name: "Apple",
    sites: ["apple.com", "icloud.com"],
    hosts: ["appleid.apple.com", "account.apple.com", "www.apple.com", "www.icloud.com", "icloud.com", "idmsa.apple.com", "appleid.cdn-apple.com"],
    cdnDomains: []
  })
]);

// Host boundary is exact, HTTPS only, and cannot match suffix spoofs, credentials
// in a URL or a similarly named advertising host. The pattern is RE2-compatible.
export function exactHttpsHostPattern(host) {
  return "^https:\\/\\/" + host.replaceAll(".", "\\.") + "(?::443)?\\/";
}

export function secureCdnHostPattern(domains) {
  return "^https:\\/\\/(?:[a-z0-9-]+\\.)*(?:" +
    domains.map((domain) => domain.replaceAll(".", "\\.")).join("|") +
    ")(?::443)?\\/";
}

export function buildLoginCompatibilityRules(enabled = true) {
  if (enabled !== true) return [];
  const rules = [];
  const add = (condition) => rules.push({
    id: RULE_BASE + rules.length,
    priority: LOGIN_COMPATIBILITY_PRIORITY,
    action: { type: "allow" },
    condition
  });
  // Main-frame login/site navigation may begin from any other site. This does not
  // allow frames or background trackers on that originating site.
  const navigableHosts = [...new Set(LOGIN_COMPATIBILITY_GROUPS.flatMap((group) =>
    group.hosts.filter((host) => group.sites.some((site) => host === site || host.endsWith("." + site)))
  ))];
  for (const host of navigableHosts) {
    add({ regexFilter: exactHttpsHostPattern(host), resourceTypes: ["main_frame"] });
  }
  for (const group of LOGIN_COMPATIBILITY_GROUPS) {
    for (const host of group.hosts) {
      add({
        regexFilter: exactHttpsHostPattern(host),
        initiatorDomains: [...group.sites],
        excludedInitiatorDomains: [...EXCLUDED_INITIATORS],
        resourceTypes: [...RESOURCE_TYPES]
      });
    }
    if (group.cdnDomains.length) {
      add({
        regexFilter: secureCdnHostPattern(group.cdnDomains),
        requestDomains: [...group.cdnDomains],
        initiatorDomains: [...group.sites],
        excludedInitiatorDomains: [...EXCLUDED_INITIATORS],
        resourceTypes: [...RESOURCE_TYPES]
      });
    }
  }
  return rules;
}

export function loginCompatibilityRuleIds() {
  return buildLoginCompatibilityRules().map((rule) => rule.id);
}
