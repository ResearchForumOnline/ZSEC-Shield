import {
  DEFAULT_SETTINGS,
  buildPauseRules,
  domainFromUrl,
  normalizeDomain,
  normalizeSettings,
  pauseRuleIds
} from "./policy.js";
import { buildHighRiskRulesForSettings, highRiskRuleIds } from "./high-risk-browsing.js";
import {
  EXPECTED_RULESET_IDS,
  verifyDnrRuntime
} from "./runtime-health.js";
import { applyVerifiedSettings } from "./settings-transaction.js";

const HEALTH_KEY = "runtimeHealth";
const RULESET_IDS = EXPECTED_RULESET_IDS;

async function readRuntimeHealth() {
  const stored = await chrome.storage.local.get(HEALTH_KEY);
  const health = stored[HEALTH_KEY];
  const extensionVersion = chrome.runtime.getManifest().version;
  return health && typeof health === "object" &&
    health.schema === "zsec.browser-shields.runtime-health.v2" &&
    health.extensionVersion === extensionVersion &&
    typeof health.ok === "boolean"
    ? health
    : {
        schema: "zsec.browser-shields.runtime-health.v2",
        extensionVersion,
        state: "unchecked",
        ok: false,
        error: "Local filtering has not been verified",
        diagnostic: "health_record_absent",
        details: null,
        recordedAt: null
      };
}

function buildRuntimeHealth(ok, error = null, details = null, state = null) {
  return {
    ok,
    schema: "zsec.browser-shields.runtime-health.v2",
    extensionVersion: chrome.runtime.getManifest().version,
    state: state || (ok ? details?.filteringMode === "off" ? "disabled_by_user" : "verified" : "degraded"),
    error: ok ? null : "Local filtering verification failed",
    diagnostic: ok ? null : error instanceof Error ? error.message : "unknown_failure",
    details: ok && details ? details : null,
    recordedAt: new Date().toISOString()
  };
}

async function recordRuntimeHealth(ok, error = null, details = null, state = null) {
  const health = buildRuntimeHealth(ok, error, details, state);
  await chrome.storage.local.set({ [HEALTH_KEY]: health });
  if (!ok) {
    await Promise.allSettled([
      chrome.action.setBadgeText({ text: "!" }),
      chrome.action.setBadgeBackgroundColor({ color: "#b42318" })
    ]);
  }
  return health;
}

async function readSettings() {
  const stored = await chrome.storage.local.get(DEFAULT_SETTINGS);
  return normalizeSettings(stored);
}

async function applyNetworkSettings(normalized) {
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
}

async function writeSettings(settings) {
  const normalized = normalizeSettings(settings);
  const previous = await readSettings();
  const result = await applyVerifiedSettings({
    desired: normalized,
    previous,
    apply: applyNetworkSettings,
    verify: (candidate) => {
      const expectedDynamicRuleIds = [
        ...buildPauseRules(candidate.protectionEnabled ? candidate.pausedSites : []),
        ...buildHighRiskRulesForSettings(candidate)
      ].map((rule) => rule.id);
      return verifyDnrRuntime(chrome, candidate.protectionEnabled, expectedDynamicRuleIds);
    },
    persist: async (candidate, runtime, rollback) => {
      if (rollback) {
        await chrome.storage.local.set(candidate);
        await updateBadge(candidate);
        return;
      }
      const health = buildRuntimeHealth(true, null, runtime);
      await chrome.storage.local.set({ ...candidate, [HEALTH_KEY]: health });
      await updateBadge(candidate);
    },
    recordFailure: async ({ error, rollback, rollbackError }) => {
      const diagnostic = new Error(
        `${error instanceof Error ? error.message : "unknown_failure"};rollback_${rollback}` +
        (rollbackError instanceof Error ? `:${rollbackError.message}` : "")
      );
      await recordRuntimeHealth(false, diagnostic, null, "degraded");
    }
  });
  return result.settings;
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
    console.error("ZSEC filtering initialization failed closed", error);
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
