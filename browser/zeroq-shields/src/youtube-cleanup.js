(() => {
  "use strict";

  const host = location.hostname.toLowerCase();
  if (window.top !== window || (host !== "www.youtube.com" && host !== "m.youtube.com")) return;

  const SKIP_SELECTORS = [
    ".ytp-ad-skip-button-modern",
    ".ytp-ad-skip-button",
    ".ytp-ad-skip-button-slot button",
    ".ytp-skip-ad-button",
    "button.ytp-skip-ad-button",
    ".ytp-ad-overlay-close-button"
  ];
  const EASYLIST_COSMETIC_SELECTORS = Array.isArray(
    globalThis.ZSEC_YOUTUBE_COSMETIC_SELECTORS
  ) ? globalThis.ZSEC_YOUTUBE_COSMETIC_SELECTORS : [];
  const HIDE_SELECTORS = Array.from(new Set([
    "#masthead-ad",
    "#player-ads",
    "[target-id=\"engagement-panel-ads\"]",
    "[layout*=\"display-ad-\"]",
    ".ytp-ad-overlay-container",
    ".ytp-ad-player-overlay",
    "ytd-action-companion-ad-renderer",
    "ytd-ad-slot-renderer",
    "ytd-banner-promo-renderer",
    "ytd-display-ad-renderer",
    "ytd-promoted-video-renderer",
    "ytd-promoted-sparkles-web-renderer",
    "ytd-promoted-sparkles-text-search-renderer",
    "ytd-in-feed-ad-layout-renderer",
    "ytd-rich-item-renderer:has(> #content > ytd-ad-slot-renderer)",
    "ytd-search-pyv-renderer",
    ...EASYLIST_COSMETIC_SELECTORS
  ]));
  let enabled = false;
  let disposed = false;
  let observing = false;
  let queued = false;
  let lastClicked = null;
  let settings = {
    protectionEnabled: true,
    youtubeCleanup: true,
    pausedSites: []
  };

  const observer = new MutationObserver(schedule);

  function installStyle() {
    if (document.getElementById("zeroq-youtube-style")) return true;
    if (!document.documentElement) return false;
    const style = document.createElement("style");
    style.id = "zeroq-youtube-style";
    style.textContent = `${HIDE_SELECTORS.join(",")} { display: none !important; visibility: hidden !important; }`;
    document.documentElement.appendChild(style);
    return true;
  }

  function removeStyle() {
    document.getElementById("zeroq-youtube-style")?.remove();
  }

  function clean() {
    queued = false;
    if (!enabled || disposed) return;
    if (!installStyle()) return;

    let visibleButton = null;
    for (const selector of SKIP_SELECTORS) {
      const button = document.querySelector(selector);
      if (!(button instanceof HTMLElement) || button.offsetParent === null) continue;
      if (button.disabled === true || button.getAttribute("aria-disabled") === "true") continue;
      visibleButton = button;
      if (button !== lastClicked) button.click();
      break;
    }
    lastClicked = visibleButton;
  }

  function schedule() {
    if (queued || !enabled || disposed) return;
    queued = true;
    requestAnimationFrame(clean);
  }

  function start() {
    if (!enabled || disposed) return;
    if (!observing) {
      observer.observe(document, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ["class", "style", "hidden", "aria-disabled"]
      });
      observing = true;
    }
    schedule();
  }

  function stop() {
    observer.disconnect();
    observing = false;
    lastClicked = null;
    removeStyle();
  }

  function hostIsPaused(pausedSites) {
    if (!Array.isArray(pausedSites)) return false;
    return pausedSites.some((value) => {
      if (typeof value !== "string") return false;
      const paused = value.trim().toLowerCase().replace(/^\.+|\.+$/g, "");
      return paused && (host === paused || host.endsWith(`.${paused}`));
    });
  }

  function applySettings(next) {
    settings = {
      protectionEnabled: next.protectionEnabled !== false,
      youtubeCleanup: next.youtubeCleanup !== false,
      pausedSites: Array.isArray(next.pausedSites) ? [...next.pausedSites] : []
    };
    enabled = settings.protectionEnabled && settings.youtubeCleanup && !hostIsPaused(settings.pausedSites);
    if (enabled) start();
    else stop();
  }

  chrome.storage.local.get(settings, (stored) => {
    if (chrome.runtime.lastError) {
      enabled = false;
      stop();
      return;
    }
    applySettings(stored);
  });

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== "local") return;
    if (!changes.youtubeCleanup && !changes.protectionEnabled && !changes.pausedSites) return;
    const next = { ...settings };
    for (const key of ["youtubeCleanup", "protectionEnabled", "pausedSites"]) {
      if (changes[key]) next[key] = changes[key].newValue;
    }
    applySettings(next);
  });

  document.addEventListener("yt-navigate-finish", schedule, { passive: true });
  window.addEventListener("pagehide", () => {
    disposed = true;
    stop();
  }, { once: true });
})();
