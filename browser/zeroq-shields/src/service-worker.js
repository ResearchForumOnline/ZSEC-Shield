import {
  DEFAULT_SETTINGS,
  buildPauseRules,
  domainFromUrl,
  normalizeDomain,
  normalizeSettings,
  pauseRuleIds
} from "./policy.js";
import { buildHighRiskRulesForSettings, highRiskRuleIds } from "./high-risk-browsing.js";

const HEALTH_KEY = "runtimeHealth";
const RULESET_IDS = Object.freeze(["privacy_rules", "link_cleanup"]);

async function readRuntimeHealth() {
  const stored = await chrome.storage.local.get(HEALTH_KEY);
  const health = stored[HEALTH_KEY];
  return health && typeof health === "object" ? health : { ok: true, error: null };
}

async function recordRuntimeHealth(ok, error = null) {
  const health = {
    ok,
    error: ok ? null : "Local filtering initialization failed",
    recordedAt: new Date().toISOString()
  };
  await chrome.storage.local.set({ [HEALTH_KEY]: health });
  if (!ok) {
    await Promise.allSettled([
      chrome.action.setBadgeText({ text: "!" }),
      chrome.action.setBadgeBackgroundColor({ color: "#b42318" })
    ]);
  }
  if (error) throw error;
  return health;
}

async function readSettings() {
  const stored = await chrome.storage.local.get(DEFAULT_SETTINGS);
  return normalizeSettings(stored);
}

async function writeSettings(settings) {
  try {
    const normalized = normalizeSettings(settings);
    await chrome.storage.local.set(normalized);
    await chrome.declarativeNetRequest.updateEnabledRulesets({
      enableRulesetIds: normalized.protectionEnabled ? [...RULESET_IDS] : [],
      disableRulesetIds: normalized.protectionEnabled ? [] : [...RULESET_IDS]
    });
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: [...pauseRuleIds(), ...highRiskRuleIds()],
      addRules: [
        ...buildPauseRules(normalized.protectionEnabled ? normalized.pausedSites : []),
        ...buildHighRiskRulesForSettings(normalized)
      ]
    });
    await updateBadge(normalized);
    await recordRuntimeHealth(true);
    return normalized;
  } catch (error) {
    return recordRuntimeHealth(false, error);
  }
}

async function updateBadge(settings) {
  const highRiskActive = settings.protectionEnabled && settings.highRiskMode;
  const text = highRiskActive ? "HIGH" : settings.protectionEnabled ? "ON" : "OFF";
  await chrome.action.setBadgeText({ text });
  await chrome.action.setBadgeBackgroundColor({
    color: highRiskActive ? "#b54708" : settings.protectionEnabled ? "#00a77a" : "#68727d"
  });
}

async function initialiseRules() {
  try {
    await writeSettings(await readSettings());
  } catch (error) {
    try {
      await recordRuntimeHealth(false);
    } catch (healthError) {
      console.error("ZSEC runtime health could not be persisted", healthError, error);
    }
  }
}

chrome.runtime.onInstalled.addListener(() => {
  void initialiseRules();
});

chrome.runtime.onStartup.addListener(() => {
  void initialiseRules();
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
        health: await readRuntimeHealth(),
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
    if (message.type === "setHighRiskMode") {
      settings.highRiskMode = message.enabled === true;
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
