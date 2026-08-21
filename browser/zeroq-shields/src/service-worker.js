import {
  DEFAULT_SETTINGS,
  buildPauseRules,
  domainFromUrl,
  normalizeDomain,
  normalizeSettings,
  pauseRuleIds
} from "./policy.js";

async function readSettings() {
  const stored = await chrome.storage.local.get(DEFAULT_SETTINGS);
  return normalizeSettings(stored);
}

async function writeSettings(settings) {
  const normalized = normalizeSettings(settings);
  await chrome.storage.local.set(normalized);
  await chrome.declarativeNetRequest.updateEnabledRulesets({
    enableRulesetIds: normalized.protectionEnabled ? ["privacy_rules"] : [],
    disableRulesetIds: normalized.protectionEnabled ? [] : ["privacy_rules"]
  });
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: pauseRuleIds(),
    addRules: buildPauseRules(normalized.pausedSites)
  });
  await updateBadge(normalized);
  return normalized;
}

async function updateBadge(settings) {
  const text = settings.protectionEnabled ? "ON" : "OFF";
  await chrome.action.setBadgeText({ text });
  await chrome.action.setBadgeBackgroundColor({
    color: settings.protectionEnabled ? "#00a77a" : "#68727d"
  });
}

chrome.runtime.onInstalled.addListener(() => {
  readSettings().then(writeSettings).catch(() => undefined);
});

chrome.runtime.onStartup.addListener(() => {
  readSettings().then(writeSettings).catch(() => undefined);
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const respond = async () => {
    const settings = await readSettings();
    if (!message || typeof message !== "object") {
      throw new Error("Invalid request");
    }
    if (message.type === "getStatus") {
      const domain = domainFromUrl(message.url || sender.tab?.url || "");
      return {
        ok: true,
        settings,
        domain,
        sitePaused: domain ? settings.pausedSites.includes(domain) : false
      };
    }
    if (message.type === "setProtection") {
      settings.protectionEnabled = message.enabled === true;
      return { ok: true, settings: await writeSettings(settings) };
    }
    if (message.type === "setYoutubeCleanup") {
      settings.youtubeCleanup = message.enabled === true;
      return { ok: true, settings: await writeSettings(settings) };
    }
    if (message.type === "setSitePaused") {
      const domain = normalizeDomain(message.domain);
      if (!domain) throw new Error("This page cannot be paused");
      const paused = new Set(settings.pausedSites);
      if (message.paused === true) paused.add(domain);
      else paused.delete(domain);
      settings.pausedSites = [...paused].sort();
      return { ok: true, settings: await writeSettings(settings) };
    }
    throw new Error("Unsupported request");
  };
  respond().then(sendResponse).catch((error) => {
    sendResponse({ ok: false, error: error instanceof Error ? error.message : "Request failed" });
  });
  return true;
});
