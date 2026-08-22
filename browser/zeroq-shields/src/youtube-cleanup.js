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
  const HIDE_SELECTORS = [
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
    "ytd-search-pyv-renderer"
  ];
  let enabled = false;
  let disposed = false;
  let observing = false;
  let queued = false;
  let lastClicked = null;

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
      observer.observe(document, { childList: true, subtree: true });
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

  chrome.storage.local.get({ youtubeCleanup: true }, (stored) => {
    if (chrome.runtime.lastError) {
      enabled = false;
      stop();
      return;
    }
    enabled = stored.youtubeCleanup !== false;
    if (enabled) start();
    else stop();
  });

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== "local" || !changes.youtubeCleanup) return;
    enabled = changes.youtubeCleanup.newValue !== false;
    if (enabled) start();
    else stop();
  });

  document.addEventListener("yt-navigate-finish", schedule, { passive: true });
  window.addEventListener("pagehide", () => {
    disposed = true;
    stop();
  }, { once: true });
})();
