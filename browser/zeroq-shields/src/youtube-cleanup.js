(() => {
  "use strict";

  const SKIP_SELECTORS = [
    ".ytp-ad-skip-button-modern",
    ".ytp-ad-skip-button",
    ".ytp-skip-ad-button",
    ".ytp-ad-overlay-close-button"
  ];
  const HIDE_SELECTORS = [
    ".ytp-ad-overlay-container",
    "ytd-ad-slot-renderer",
    "ytd-display-ad-renderer",
    "ytd-promoted-video-renderer",
    "ytd-promoted-sparkles-web-renderer",
    "ytd-in-feed-ad-layout-renderer"
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
      if (button instanceof HTMLElement && button.offsetParent !== null) button.click();
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

  new MutationObserver(schedule).observe(document, { childList: true, subtree: true });
  document.addEventListener("yt-navigate-finish", schedule, { passive: true });
})();
