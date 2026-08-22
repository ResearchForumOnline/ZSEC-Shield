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
  RUNTIME_HEALTH_SCHEMA,
  RUNTIME_POLICY_REVISION,
  settingsRevision,
  verifyDnrRuntime
} from "./runtime-health.js";
import { applyVerifiedSettings } from "./settings-transaction.js";

const HEALTH_KEY = "runtimeHealth";
const RULESET_IDS = EXPECTED_RULESET_IDS;
let operationQueue = Promise.resolve();

function enqueueOperation(operation) {
  const run = operationQueue.then(operation);
  operationQueue = run.then(() => undefined, () => undefined);
  return run;
}

function safeDiagnostic(error) {
  const value = error instanceof Error ? error.message : "unknown_failure";
  return /^[a-z0-9_:;-]+$/.test(value) ? value : "runtime_api_failure";
}

async function readSettings() {
  const stored = await chrome.storage.local.get(DEFAULT_SETTINGS);
  return normalizeSettings(stored);
}

function buildRuntimeHealth(ok, settings, error = null, details = null, state = null) {
  const representativeUnavailable = details?.representativeMatchStatus === "api_unavailable";
  return {
    ok,
    schema: RUNTIME_HEALTH_SCHEMA,
    extensionVersion: chrome.runtime.getManifest().version,
    policyRevision: RUNTIME_POLICY_REVISION,
    settingsRevision: settingsRevision(settings),
    state: state || (ok
      ? details?.filteringMode === "off"
        ? "disabled_by_user"
        : representativeUnavailable ? "verified_limited" : "verified"
      : "degraded"),
    error: ok ? null : "Local filtering verification failed",
    diagnostic: ok ? null : safeDiagnostic(error),
    details: ok && details ? details : null,
    recordedAt: new Date().toISOString()
  };
}

async function recordRuntimeHealth(health) {
  await chrome.storage.local.set({ [HEALTH_KEY]: health });
  if (!health.ok) {
    await Promise.allSettled([
      chrome.action.setBadgeText({ text: "!" }),
      chrome.action.setBadgeBackgroundColor({ color: "#b42318" })
    ]);
  }
  return health;
}

function dynamicRulesFor(settings) {
  return [
    ...buildPauseRules(settings.protectionEnabled ? settings.pausedSites : []),
    ...buildHighRiskRulesForSettings(settings)
  ];
}

async function applyNetworkSettings(normalized) {
  await chrome.declarativeNetRequest.updateEnabledRulesets({
    enableRulesetIds: normalized.protectionEnabled ? [...RULESET_IDS] : [],
    disableRulesetIds: normalized.protectionEnabled ? [] : [...RULESET_IDS]
  });
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: [...pauseRuleIds(), ...highRiskRuleIds()],
    addRules: dynamicRulesFor(normalized)
  });
}

function verifyNetworkSettings(candidate) {
  return verifyDnrRuntime(
    chrome,
    candidate.protectionEnabled,
    dynamicRulesFor(candidate)
  );
}

async function updateBadge(settings) {
  const highRiskActive = settings.protectionEnabled && settings.highRiskMode;
  const text = highRiskActive ? "HIGH" : settings.protectionEnabled ? "ON" : "OFF";
  await Promise.allSettled([
    chrome.action.setBadgeText({ text }),
    chrome.action.setBadgeBackgroundColor({
      color: highRiskActive ? "#b54708" : settings.protectionEnabled ? "#00a77a" : "#68727d"
    })
  ]);
}

async function writeSettings(settings) {
  const normalized = normalizeSettings(settings);
  const previous = await readSettings();
  let committedHealth = null;
  const result = await applyVerifiedSettings({
    desired: normalized,
    previous,
    apply: applyNetworkSettings,
    verify: verifyNetworkSettings,
    persist: async (candidate, runtime, rollback) => {
      if (rollback) {
        await chrome.storage.local.set(candidate);
        await updateBadge(candidate);
        return;
      }
      committedHealth = buildRuntimeHealth(true, candidate, null, runtime);
      await chrome.storage.local.set({ ...candidate, [HEALTH_KEY]: committedHealth });
      await updateBadge(candidate);
    },
    recordFailure: async ({ error, rollback, rollbackError }) => {
      const diagnostic = new Error(
        `${safeDiagnostic(error)};rollback_${rollback}` +
        (rollbackError ? `:${safeDiagnostic(rollbackError)}` : "")
      );
      await recordRuntimeHealth(
        buildRuntimeHealth(false, previous, diagnostic, null, "degraded")
      );
    }
  });
  return { settings: result.settings, health: committedHealth };
}

async function refreshRuntimeHealth(settings) {
  try {
    const details = await verifyNetworkSettings(settings);
    const health = buildRuntimeHealth(true, settings, null, details);
    await recordRuntimeHealth(health);
    await updateBadge(settings);
    return health;
  } catch (error) {
    return recordRuntimeHealth(
      buildRuntimeHealth(false, settings, error, null, "degraded")
    );
  }
}

async function initialiseRules() {
  await writeSettings(await readSettings());
}

function initialiseSafely() {
  void enqueueOperation(initialiseRules).catch((error) => {
    console.error("ZSEC filtering initialization failed closed", error);
  });
}

chrome.runtime.onInstalled.addListener(initialiseSafely);
chrome.runtime.onStartup.addListener(initialiseSafely);

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const respond = async () => {
    if (!message || typeof message !== "object") throw new Error("Invalid request");
    if (message.type === "getStatus") {
      const settings = await readSettings();
      const health = await refreshRuntimeHealth(settings);
      const domain = domainFromUrl(message.url || sender.tab?.url || "");
      return {
        ok: true,
        settings,
        health,
        domain,
        sitePaused: domain ? settings.pausedSites.includes(domain) : false
      };
    }

    const settings = await readSettings();
    if (message.type === "setProtection") settings.protectionEnabled = message.enabled === true;
    else if (message.type === "setYoutubeCleanup") settings.youtubeCleanup = message.enabled === true;
    else if (message.type === "setHighRiskMode") settings.highRiskMode = message.enabled === true;
    else if (message.type === "setSitePaused") {
      const domain = normalizeDomain(message.domain);
      if (!domain) throw new Error("This page cannot be paused");
      const paused = new Set(settings.pausedSites);
      if (message.paused === true) paused.add(domain);
      else paused.delete(domain);
      settings.pausedSites = [...paused].sort();
    } else {
      throw new Error("Unsupported request");
    }
    const result = await writeSettings(settings);
    return { ok: true, settings: result.settings, health: result.health };
  };

  enqueueOperation(respond).then(sendResponse).catch((error) => {
    sendResponse({
      ok: false,
      error: error instanceof Error
        ? "Local filtering settings could not be verified; the previous settings were restored."
        : "Request failed"
    });
  });
  return true;
});
