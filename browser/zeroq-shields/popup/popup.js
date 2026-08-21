const protection = document.querySelector("#protection");
const youtube = document.querySelector("#youtube");
const pauseSite = document.querySelector("#pause-site");
const domainLabel = document.querySelector("#domain");
const status = document.querySelector(".status");
const message = document.querySelector("#message");
let currentDomain = null;

async function send(payload) {
  const response = await chrome.runtime.sendMessage(payload);
  if (!response?.ok) throw new Error(response?.error || "ZeroQ request failed");
  return response;
}

function showError(error) {
  message.textContent = error instanceof Error ? error.message : "The setting could not be changed.";
}

function apply(settings, sitePaused = pauseSite.checked, health = { ok: true }) {
  protection.checked = settings.protectionEnabled;
  youtube.checked = settings.youtubeCleanup;
  pauseSite.checked = sitePaused;
  const unavailable = health?.ok === false;
  protection.disabled = unavailable;
  youtube.disabled = unavailable;
  pauseSite.disabled = unavailable || !currentDomain;
  status.textContent = unavailable
    ? "Filtering state unavailable"
    : settings.protectionEnabled
      ? "ZeroQ rules are on"
      : "ZeroQ rules are off";
  if (unavailable) message.textContent = health.error || "Extension initialization failed";
}

async function initialise() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const response = await send({ type: "getStatus", url: tab?.url || "" });
  currentDomain = response.domain;
  domainLabel.textContent = currentDomain || "Unavailable on this page";
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
