import {
  UNCHECKED_HEALTH,
  healthPresentation,
  normalizeContextDomain
} from "../src/popup-state.js";

const protection = document.querySelector("#protection");
const youtube = document.querySelector("#youtube");
const highRisk = document.querySelector("#high-risk");
const pauseSite = document.querySelector("#pause-site");
const domainLabel = document.querySelector("#domain");
const status = document.querySelector(".status");
const coverage = document.querySelector("#coverage");
const message = document.querySelector("#message");
let currentDomain = null;
const pageParameters = new URLSearchParams(location.search);
const tabSurface = pageParameters.get("surface") === "tab";
if (tabSurface) document.body.classList.add("tab-surface");

async function send(payload) {
  const response = await chrome.runtime.sendMessage(payload);
  if (!response?.ok) throw new Error(response?.error || "ZSEC request failed");
  return response;
}

function showError(error) {
  protection.disabled = true;
  highRisk.disabled = true;
  youtube.disabled = true;
  pauseSite.disabled = true;
  message.textContent = error instanceof Error ? error.message : "The setting could not be changed.";
}

function apply(settings, sitePaused = pauseSite.checked, health = UNCHECKED_HEALTH) {
  protection.checked = settings.protectionEnabled;
  highRisk.checked = settings.highRiskMode;
  youtube.checked = settings.youtubeCleanup;
  pauseSite.checked = sitePaused;
  const presentation = healthPresentation(settings, health);
  const unavailable = presentation.unavailable;
  protection.disabled = unavailable;
  highRisk.disabled = unavailable || !settings.protectionEnabled;
  youtube.disabled = unavailable;
  pauseSite.disabled = unavailable || !currentDomain || !settings.protectionEnabled || settings.highRiskMode;
  domainLabel.textContent = settings.highRiskMode && settings.protectionEnabled
    ? "Unavailable while High-Risk Browsing is active"
    : currentDomain || "Unavailable on this page";
  status.textContent = presentation.status;
  coverage.textContent = presentation.coverage;
  message.textContent = presentation.message;
}

async function initialise() {
  const contextualSite = tabSurface
    ? normalizeContextDomain(pageParameters.get("site"))
    : null;
  const [tab] = contextualSite ? [] : await chrome.tabs.query({ active: true, currentWindow: true });
  const response = await send({
    type: "getStatus",
    url: contextualSite ? `https://${contextualSite}/` : tab?.url || ""
  });
  currentDomain = response.domain;
  apply(response.settings, response.sitePaused, response.health);
  return response;
}

async function recoverAfterSettingFailure(error) {
  const originalMessage = error instanceof Error ? error.message : "The setting could not be changed.";
  showError(error);
  try {
    const response = await initialise();
    if (response.health?.ok === true) message.textContent = originalMessage;
  } catch (verificationError) {
    showError(verificationError);
  }
}

protection.addEventListener("change", async () => {
  try {
    const response = await send({ type: "setProtection", enabled: protection.checked });
    apply(response.settings, pauseSite.checked, response.health);
  } catch (error) {
    await recoverAfterSettingFailure(error);
  }
});

highRisk.addEventListener("change", async () => {
  try {
    const response = await send({ type: "setHighRiskMode", enabled: highRisk.checked });
    apply(response.settings, pauseSite.checked, response.health);
  } catch (error) {
    await recoverAfterSettingFailure(error);
  }
});

youtube.addEventListener("change", async () => {
  try {
    const response = await send({ type: "setYoutubeCleanup", enabled: youtube.checked });
    apply(response.settings, pauseSite.checked, response.health);
  } catch (error) {
    await recoverAfterSettingFailure(error);
  }
});

pauseSite.addEventListener("change", async () => {
  try {
    const response = await send({
      type: "setSitePaused",
      domain: currentDomain,
      paused: pauseSite.checked
    });
    apply(
      response.settings,
      response.settings.pausedSites.includes(currentDomain),
      response.health
    );
  } catch (error) {
    await recoverAfterSettingFailure(error);
  }
});

initialise().catch(showError);
