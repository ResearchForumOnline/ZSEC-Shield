import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import test from "node:test";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const cosmeticSource = await readFile(join(root, "src", "youtube-cosmetic-rules.js"), "utf8");
const source = await readFile(join(root, "src", "youtube-cleanup.js"), "utf8");

function makeHarness({ hostname = "www.youtube.com", topFrame = true } = {}) {
  const frames = [];
  const elementsById = new Map();
  const selectorResults = new Map();
  const documentListeners = new Map();
  const windowListeners = new Map();
  const storageCallbacks = [];
  const storageListeners = [];
  const observers = [];

  class FakeElement {
    constructor(tagName = "div") {
      this.tagName = tagName.toUpperCase();
      this.id = "";
      this.textContent = "";
      this.offsetParent = {};
      this.disabled = false;
      this.attributes = new Map();
      this.clickCount = 0;
    }

    appendChild(child) {
      if (child.id) elementsById.set(child.id, child);
      child.remove = () => elementsById.delete(child.id);
      return child;
    }

    click() {
      this.clickCount += 1;
    }

    getAttribute(name) {
      return this.attributes.get(name) ?? null;
    }

    setAttribute(name, value) {
      this.attributes.set(name, String(value));
    }
  }

  class FakeMutationObserver {
    constructor(callback) {
      this.callback = callback;
      this.observeCalls = [];
      this.disconnectCount = 0;
      this.connected = false;
      observers.push(this);
    }

    observe(target, options) {
      this.observeCalls.push({ target, options });
      this.connected = true;
    }

    disconnect() {
      this.disconnectCount += 1;
      this.connected = false;
    }
  }

  const documentElement = new FakeElement("html");
  const document = {
    documentElement,
    createElement: (tagName) => new FakeElement(tagName),
    getElementById: (id) => elementsById.get(id) ?? null,
    querySelector: (selector) => selectorResults.get(selector) ?? null,
    addEventListener(type, callback) {
      documentListeners.set(type, callback);
    }
  };

  const window = {
    addEventListener(type, callback) {
      windowListeners.set(type, callback);
    }
  };
  window.top = topFrame ? window : {};

  const chrome = {
    runtime: { lastError: undefined },
    storage: {
      local: {
        get(defaults, callback) {
          storageCallbacks.push({ defaults, callback });
        }
      },
      onChanged: {
        addListener(callback) {
          storageListeners.push(callback);
        }
      }
    }
  };

  const context = {
    chrome,
    console,
    document,
    HTMLElement: FakeElement,
    location: { hostname },
    MutationObserver: FakeMutationObserver,
    requestAnimationFrame(callback) {
      frames.push(callback);
      return frames.length;
    },
    window
  };
  vm.runInNewContext(cosmeticSource, context, { filename: "youtube-cosmetic-rules.js" });
  vm.runInNewContext(source, context, { filename: "youtube-cleanup.js" });

  return {
    chrome,
    document,
    documentListeners,
    elementsById,
    frames,
    FakeElement,
    observers,
    selectorResults,
    storageCallbacks,
    storageListeners,
    windowListeners,
    flushFrame() {
      const callback = frames.shift();
      if (callback) callback();
    },
    resolveStorage(value, error) {
      const pending = storageCallbacks.shift();
      assert.ok(pending, "expected a pending storage read");
      chrome.runtime.lastError = error;
      pending.callback(
        value && typeof value === "object"
          ? { ...pending.defaults, ...value }
          : { ...pending.defaults, youtubeCleanup: value }
      );
      chrome.runtime.lastError = undefined;
    }
  };
}

test("runs only in a top-level allowlisted YouTube document", () => {
  const wrongHost = makeHarness({ hostname: "youtube.example" });
  assert.equal(wrongHost.storageCallbacks.length, 0);
  assert.equal(wrongHost.observers.length, 0);

  const subframe = makeHarness({ topFrame: false });
  assert.equal(subframe.storageCallbacks.length, 0);
  assert.equal(subframe.observers.length, 0);
});

test("waits for local preference before observing or changing the page", () => {
  const harness = makeHarness();
  assert.equal(harness.observers.length, 1);
  assert.equal(harness.observers[0].connected, false);

  harness.observers[0].callback([]);
  assert.equal(harness.frames.length, 0);

  harness.resolveStorage(false);
  assert.equal(harness.observers[0].connected, false);
  assert.equal(harness.elementsById.has("zeroq-youtube-style"), false);
});

test("clicks a visible enabled skip control once per appearance", () => {
  const harness = makeHarness();
  const button = new harness.FakeElement("button");
  harness.selectorResults.set(".ytp-ad-skip-button-modern", button);

  harness.resolveStorage(true);
  assert.equal(harness.observers[0].observeCalls[0].options.childList, true);
  assert.equal(harness.observers[0].observeCalls[0].options.subtree, true);
  assert.equal(harness.observers[0].observeCalls[0].options.attributes, true);
  assert.deepEqual(
    Array.from(harness.observers[0].observeCalls[0].options.attributeFilter),
    ["class", "style", "hidden", "aria-disabled"]
  );
  harness.flushFrame();
  assert.equal(button.clickCount, 1);
  const style = harness.elementsById.get("zeroq-youtube-style").textContent;
  assert.match(style, /#player-ads/);
  assert.match(style, /engagement-panel-ads/);
  assert.match(style, /ytd-rich-item-renderer:has/);
  assert.match(style, /ytm-companion-slot\[data-content-type\]/);

  harness.observers[0].callback([]);
  harness.flushFrame();
  assert.equal(button.clickCount, 1, "the same live control must not be clicked repeatedly");

  harness.selectorResults.delete(".ytp-ad-skip-button-modern");
  harness.observers[0].callback([]);
  harness.flushFrame();
  harness.selectorResults.set(".ytp-ad-skip-button-modern", button);
  harness.observers[0].callback([]);
  harness.flushFrame();
  assert.equal(button.clickCount, 2, "a control may be used again after it disappears and returns");
});

test("does not click hidden or disabled controls", () => {
  const harness = makeHarness();
  const button = new harness.FakeElement("button");
  button.offsetParent = null;
  harness.selectorResults.set(".ytp-ad-skip-button-modern", button);
  harness.resolveStorage(true);
  harness.flushFrame();
  assert.equal(button.clickCount, 0);

  button.offsetParent = {};
  button.disabled = true;
  harness.observers[0].callback([]);
  harness.flushFrame();
  assert.equal(button.clickCount, 0);

  button.disabled = false;
  button.setAttribute("aria-disabled", "true");
  harness.observers[0].callback([]);
  harness.flushFrame();
  assert.equal(button.clickCount, 0);
});

test("preference changes stop and restart the bounded observer", () => {
  const harness = makeHarness();
  harness.resolveStorage(true);
  harness.flushFrame();
  assert.equal(harness.observers[0].connected, true);
  assert.equal(harness.elementsById.has("zeroq-youtube-style"), true);

  harness.storageListeners[0]({ youtubeCleanup: { newValue: false } }, "local");
  assert.equal(harness.observers[0].connected, false);
  assert.equal(harness.elementsById.has("zeroq-youtube-style"), false);

  harness.storageListeners[0]({ youtubeCleanup: { newValue: true } }, "local");
  assert.equal(harness.observers[0].connected, true);
  harness.flushFrame();

  harness.windowListeners.get("pagehide")();
  assert.equal(harness.observers[0].connected, false);
  harness.documentListeners.get("yt-navigate-finish")();
  assert.equal(harness.frames.length, 0);
});

test("master protection and site pause gate all YouTube page changes", () => {
  const disabled = makeHarness();
  disabled.resolveStorage({ protectionEnabled: false, youtubeCleanup: true });
  assert.equal(disabled.observers[0].connected, false);
  assert.equal(disabled.elementsById.has("zeroq-youtube-style"), false);

  const paused = makeHarness();
  paused.resolveStorage({ pausedSites: ["youtube.com"] });
  assert.equal(paused.observers[0].connected, false);
  assert.equal(paused.elementsById.has("zeroq-youtube-style"), false);

  paused.storageListeners[0]({ pausedSites: { newValue: [] } }, "local");
  assert.equal(paused.observers[0].connected, true);
  paused.flushFrame();
  assert.equal(paused.elementsById.has("zeroq-youtube-style"), true);

  paused.storageListeners[0]({ protectionEnabled: { newValue: false } }, "local");
  assert.equal(paused.observers[0].connected, false);
  assert.equal(paused.elementsById.has("zeroq-youtube-style"), false);
});

test("an attribute-only transition schedules a bounded skip check", () => {
  const harness = makeHarness();
  const button = new harness.FakeElement("button");
  button.offsetParent = null;
  harness.selectorResults.set(".ytp-ad-skip-button-modern", button);
  harness.resolveStorage(true);
  harness.flushFrame();
  assert.equal(button.clickCount, 0);

  button.offsetParent = {};
  harness.observers[0].callback([{ type: "attributes", attributeName: "class" }]);
  harness.flushFrame();
  assert.equal(button.clickCount, 1);
});

test("fails closed if the local preference cannot be read", () => {
  const harness = makeHarness();
  harness.resolveStorage(true, { message: "storage unavailable" });
  assert.equal(harness.observers[0].connected, false);
  assert.equal(harness.frames.length, 0);
  assert.equal(harness.elementsById.has("zeroq-youtube-style"), false);
});

test("contains no playback manipulation, polling, remote I/O, or dynamic code", () => {
  const forbidden = [
    /\.currentTime\s*=/,
    /\.playbackRate\s*=/,
    /\.muted\s*=/,
    /\.volume\s*=/,
    /\bsetInterval\s*\(/,
    /\b(?:fetch|XMLHttpRequest|WebSocket|EventSource)\b/,
    /\bsendBeacon\s*\(/,
    /\beval\s*\(/,
    /new\s+Function\s*\(/,
    /https?:\/\//
  ];
  for (const pattern of forbidden) {
    assert.doesNotMatch(source, pattern);
    assert.doesNotMatch(cosmeticSource, pattern);
  }
});
