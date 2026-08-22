/*
 * Deterministic YouTube cosmetic rules extracted from the pinned EasyList
 * 202608170701 source shipped with ZSEC Browser Shields.  This file contains
 * selectors only: no remote code, network access, scriptlets or playback
 * manipulation.  The retained upstream source and licence are packaged beside
 * the extension.
 */
globalThis.ZSEC_YOUTUBE_COSMETIC_SELECTORS = Object.freeze([
  ".grid.ytd-browse > #primary > .style-scope > .ytd-rich-grid-renderer > .ytd-rich-grid-renderer > .ytd-ad-slot-renderer",
  ".ytd-rich-item-renderer.style-scope > .ytd-rich-item-renderer > .ytd-ad-slot-renderer.style-scope",
  ".ytd-section-list-renderer > .ytd-item-section-renderer > ytd-search-pyv-renderer.ytd-item-section-renderer",
  ".ytd-two-column-browse-results-renderer > ytd-rich-grid-renderer > #masthead-ad.ytd-rich-grid-renderer",
  ".ytd-watch-flexy > .ytd-watch-next-secondary-results-renderer > ytd-ad-slot-renderer.ytd-watch-next-secondary-results-renderer",
  ".ytd-watch-flexy > ytd-merch-shelf-renderer > #main.ytd-merch-shelf-renderer",
  ".ytp-suggested-action > .ytp-suggested-action-badge",
  ".ytReelMetapanelViewModelHost > .ytReelMetapanelViewModelMetapanelItem > .ytShortsSuggestedActionViewModelStaticHost",
  "#contents > ytd-rich-item-renderer:has(> ytd-ad-slot-renderer)",
  "#description-inner > ytd-merch-shelf-renderer > #main.ytd-merch-shelf-renderer",
  "#shopping-timely-shelf",
  "#shorts-inner-container > .ytd-shorts:has(> .ytd-reel-video-renderer > ytd-ad-slot-renderer)",
  "#sticker-layer",
  "lazy-list > ad-slot-renderer",
  "yt-overlay-product-sticker",
  "ytd-item-section-renderer > .ytd-item-section-renderer > ytd-ad-slot-renderer.style-scope",
  "ytd-rich-item-renderer:has(> #content > ytd-ad-slot-renderer)",
  "ytm-companion-slot[data-content-type] > ytm-companion-ad-renderer",
  "ytm-rich-item-renderer > ad-slot-renderer"
]);
