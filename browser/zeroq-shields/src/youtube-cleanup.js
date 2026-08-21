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
    "ytd-search-pyv-renderer"
  ];
  let enabled = true;
  let queued = false;

  function installStyle() {
    if (document.getElementById("zeroq-youtube-style")) return;
    const style = document.createElement("style");
    style.id = "zeroq-youtube-style";
    style.textContent = `${HIDE_SELECTORS.join(",")} { display: none !important; visibility: hidden !important; }`;
    (document.documentElement || document).appendChild(style);
  }

  function removeStyle() {
    document.getElementById("zeroq-youtube-style")?.remove();
  }

  function clean() {
    queued = false;
    if (!enabled) return;
    installStyle();
    for (const selector of SKIP_SELECTORS) {
      const button = document.querySelector(selector);
      if (button instanceof HTMLElement && button.offsetParent !== null) {
        button.click();
        break;
      }
    }
  }

  function schedule() {
    if (queued || !enabled) return;
    queued = true;
    requestAnimationFrame(clean);
  }

  chrome.storage.local.get({ youtubeCleanup: true }, (stored) => {
    enabled = stored.youtubeCleanup !== false;
    if (enabled) schedule();
  });

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== "local" || !changes.youtubeCleanup) return;
    enabled = changes.youtubeCleanup.newValue !== false;
    if (enabled) schedule();
    else removeStyle();
  });

  const observer = new MutationObserver(schedule);
  observer.observe(document, { childList: true, subtree: true });
  document.addEventListener("yt-navigate-finish", schedule, { passive: true });
  window.addEventListener("pagehide", () => observer.disconnect(), { once: true });
})();
