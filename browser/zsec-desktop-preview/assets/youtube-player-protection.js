(() => {
  "use strict";

  const host = location.hostname.toLowerCase();
  if (window.top !== window || !(
    host === "youtube.com" || host.endsWith(".youtube.com") ||
    host === "youtube-nocookie.com" || host.endsWith(".youtube-nocookie.com")
  )) return;
  if (globalThis.__zsecYoutubeProtection?.version === 1) return;

  const AD_KEYS = new Set([
    "adBreakHeartbeatParams",
    "adBreakParams",
    "adParams",
    "adPlacements",
    "adPlaybackContext",
    "adSafetyReason",
    "adSignalsInfo",
    "adSlots",
    "adTrackingParams",
    "playerAds"
  ]);
  const AD_MARKER = /"(?:adPlacements|playerAds|adSlots|adBreakHeartbeatParams|adTrackingParams)"\s*:/;
  const MAX_DEPTH = 14;
  const MAX_NODES = 20000;
  const status = {
    version: 1,
    loaded: true,
    sanitizedPayloads: 0,
    removedFields: 0,
    hiddenContainers: 0,
    skipControlsUsed: 0
  };
  Object.defineProperty(globalThis, "__zsecYoutubeProtection", {
    configurable: false,
    enumerable: false,
    writable: false,
    value: status
  });

  function pruneAdvertising(root) {
    if (!root || typeof root !== "object") return root;
    const seen = new WeakSet();
    let nodes = 0;
    let removed = 0;

    function visit(value, depth) {
      if (!value || typeof value !== "object" || depth > MAX_DEPTH || nodes >= MAX_NODES) return;
      if (seen.has(value)) return;
      seen.add(value);
      nodes += 1;
      if (Array.isArray(value)) {
        for (let index = 0; index < value.length; index += 1) visit(value[index], depth + 1);
        return;
      }
      for (const key of Object.keys(value)) {
        if (AD_KEYS.has(key)) {
          try {
            delete value[key];
            removed += 1;
          } catch {
            // A frozen page object is left unchanged; protection continues elsewhere.
          }
          continue;
        }
        visit(value[key], depth + 1);
      }
    }

    visit(root, 0);
    if (removed > 0) {
      status.sanitizedPayloads += 1;
      status.removedFields += removed;
    }
    return root;
  }

  const nativeParse = JSON.parse.bind(JSON);
  JSON.parse = function zsecJsonParse(text, reviver) {
    const value = nativeParse(text, reviver);
    if (typeof text === "string" && text.length <= 16 * 1024 * 1024 && AD_MARKER.test(text)) {
      return pruneAdvertising(value);
    }
    return value;
  };

  function protectInitialObject(name) {
    const existing = Object.getOwnPropertyDescriptor(globalThis, name);
    if (existing && existing.configurable === false) {
      if ("value" in existing) pruneAdvertising(existing.value);
      return;
    }
    let stored = existing && "value" in existing ? pruneAdvertising(existing.value) : undefined;
    try {
      Object.defineProperty(globalThis, name, {
        configurable: true,
        enumerable: existing?.enumerable === true,
        get() {
          return existing?.get ? pruneAdvertising(existing.get.call(globalThis)) : stored;
        },
        set(value) {
          const cleaned = pruneAdvertising(value);
          if (existing?.set) existing.set.call(globalThis, cleaned);
          else stored = cleaned;
        }
      });
    } catch {
      // The JSON.parse and fetch boundaries remain active if a page locks this property.
    }
  }

  protectInitialObject("ytInitialPlayerResponse");
  protectInitialObject("ytInitialData");

  function isPlayerDataUrl(candidate) {
    try {
      const url = new URL(String(candidate), location.href);
      return (url.hostname === "youtube.com" || url.hostname.endsWith(".youtube.com")) &&
        (url.pathname === "/youtubei/v1/player" || url.pathname === "/get_video_info");
    } catch {
      return false;
    }
  }

  if (typeof globalThis.fetch === "function" && typeof Response === "function") {
    const nativeFetch = globalThis.fetch.bind(globalThis);
    const nativeJson = Response.prototype.json;
    const nativeText = Response.prototype.text;
    globalThis.fetch = async function zsecFetch(input, init) {
      const response = await nativeFetch(input, init);
      const candidate = typeof input === "string" || input instanceof URL ? input : input?.url;
      if (!isPlayerDataUrl(candidate)) return response;
      try {
        Object.defineProperty(response, "json", {
          configurable: true,
          value: async function zsecResponseJson() {
            return pruneAdvertising(await nativeJson.call(response));
          }
        });
        Object.defineProperty(response, "text", {
          configurable: true,
          value: async function zsecResponseText() {
            const text = await nativeText.call(response);
            if (text.length > 16 * 1024 * 1024 || !AD_MARKER.test(text)) return text;
            try {
              return JSON.stringify(pruneAdvertising(nativeParse(text)));
            } catch {
              return text;
            }
          }
        });
      } catch {
        // Keep the original response intact if this runtime does not allow own methods.
      }
      return response;
    };
  }

  const HIDE_SELECTORS = [
    "#masthead-ad",
    "#player-ads",
    ".video-ads",
    ".ytp-ad-module",
    ".ytp-ad-overlay-container",
    ".ytp-ad-player-overlay",
    "ytd-ad-slot-renderer",
    "ytd-action-companion-ad-renderer",
    "ytd-display-ad-renderer",
    "ytd-in-feed-ad-layout-renderer",
    "ytd-promoted-video-renderer",
    "ytd-promoted-sparkles-web-renderer",
    "ytd-search-pyv-renderer"
  ];
  const SKIP_SELECTORS = [
    ".ytp-ad-skip-button-modern",
    ".ytp-ad-skip-button",
    ".ytp-ad-skip-button-slot button",
    ".ytp-skip-ad-button",
    ".ytp-ad-overlay-close-button"
  ];
  let scheduled = false;
  let lastSkipControl = null;

  function cleanPage() {
    scheduled = false;
    for (const selector of HIDE_SELECTORS) {
      for (const element of document.querySelectorAll(selector)) {
        if (!(element instanceof HTMLElement) || element.dataset.zsecAdHidden === "true") continue;
        element.dataset.zsecAdHidden = "true";
        element.style.setProperty("display", "none", "important");
        element.setAttribute("aria-hidden", "true");
        status.hiddenContainers += 1;
      }
    }
    let visible = null;
    for (const selector of SKIP_SELECTORS) {
      const button = document.querySelector(selector);
      if (!(button instanceof HTMLElement) || button.offsetParent === null) continue;
      if (button.disabled === true || button.getAttribute("aria-disabled") === "true") continue;
      visible = button;
      if (button !== lastSkipControl) {
        button.click();
        status.skipControlsUsed += 1;
      }
      break;
    }
    lastSkipControl = visible;
  }

  function scheduleCleanup() {
    if (scheduled) return;
    scheduled = true;
    requestAnimationFrame(cleanPage);
  }

  const observer = new MutationObserver(scheduleCleanup);
  function startCleanup() {
    if (!document.documentElement) return;
    observer.observe(document.documentElement, { childList: true, subtree: true });
    scheduleCleanup();
  }
  if (document.documentElement) startCleanup();
  else document.addEventListener("DOMContentLoaded", startCleanup, { once: true });
  document.addEventListener("yt-navigate-finish", scheduleCleanup, { passive: true });
  window.addEventListener("pagehide", () => observer.disconnect(), { once: true });
})();
