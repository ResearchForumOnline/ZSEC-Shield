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
  message.textContent = error instanceof Error ? error.message : "The setting could not be changed.";
}

function apply(settings, sitePaused = pauseSite.checked, health = { ok: true }) {
  protection.checked = settings.protectionEnabled;
  highRisk.checked = settings.highRiskMode;
  youtube.checked = settings.youtubeCleanup;
  pauseSite.checked = sitePaused;
  const unavailable = health?.ok === false;
  protection.disabled = unavailable;
  highRisk.disabled = unavailable || !settings.protectionEnabled;
  youtube.disabled = unavailable;
  pauseSite.disabled = unavailable || !currentDomain || !settings.protectionEnabled || settings.highRiskMode;
  domainLabel.textContent = settings.highRiskMode && settings.protectionEnabled
    ? "Unavailable while High-Risk Browsing is active"
    : currentDomain || "Unavailable on this page";
  status.textContent = unavailable
    ? "Filtering state unavailable"
    : settings.protectionEnabled && settings.highRiskMode
      ? "High-Risk mode is on"
      : settings.protectionEnabled
        ? "ZSEC rules are on"
        : "ZSEC rules are off";
  const details = health?.details;
  coverage.textContent = unavailable
    ? "Coverage verification did not complete"
    : details?.filteringMode === "full"
      ? `${details.packagedStaticRuleCount.toLocaleString()} packaged rules · ${details.regexRulesVerified} regex checks passed`
      : "Filtering is intentionally paused";
  if (unavailable) {
    message.textContent = health.diagnostic
      ? `${health.error || "Extension initialization failed"} (${health.diagnostic})`
      : health.error || "Extension initialization failed";
  } else {
    message.textContent = "";
  }
}

async function initialise() {
  const contextualSite = tabSurface ? pageParameters.get("site") : null;
  const [tab] = contextualSite ? [] : await chrome.tabs.query({ active: true, currentWindow: true });
  const response = await send({
    type: "getStatus",
    url: contextualSite ? `https://${contextualSite}/` : tab?.url || ""
  });
  currentDomain = response.domain;
  apply(response.settings, response.sitePaused, response.health);
}

protection.addEventListener("change", async () => {
  try {
    const response = await send({ type: "setProtection", enabled: protection.checked });
    apply(response.settings);
  } catch (error) {
    protection.checked = !protection.checked;
    showError(error);
  }
});

highRisk.addEventListener("change", async () => {
  try {
    const response = await send({ type: "setHighRiskMode", enabled: highRisk.checked });
    apply(response.settings);
  } catch (error) {
    highRisk.checked = !highRisk.checked;
    showError(error);
  }
});

youtube.addEventListener("change", async () => {
  try {
    const response = await send({ type: "setYoutubeCleanup", enabled: youtube.checked });
    apply(response.settings);
  } catch (error) {
    youtube.checked = !youtube.checked;
    showError(error);
  }
});

pauseSite.addEventListener("change", async () => {
  try {
    const response = await send({
      type: "setSitePaused",
      domain: currentDomain,
      paused: pauseSite.checked
    });
    apply(response.settings, response.settings.pausedSites.includes(currentDomain));
  } catch (error) {
    pauseSite.checked = !pauseSite.checked;
    showError(error);
  }
});

initialise().catch(showError);
