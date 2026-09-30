import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import test from "node:test";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const source = await readFile(
  join(root, "zsec-desktop-preview", "assets", "youtube-player-protection.js"),
  "utf8"
);

function makeHarness(hostname = "www.youtube.com") {
  const selectorResults = new Map();
  const frames = [];
  const observers = [];
  const windowListeners = new Map();
  const documentListeners = new Map();

  class FakeElement {
    constructor() {
      this.dataset = {};
      this.style = { setProperty() {} };
      this.offsetParent = {};
      this.disabled = false;
      this.attributes = new Map();
      this.clickCount = 0;
    }
    setAttribute(name, value) { this.attributes.set(name, String(value)); }
    getAttribute(name) { return this.attributes.get(name) ?? null; }
    click() { this.clickCount += 1; }
  }

  class FakeMutationObserver {
    constructor(callback) {
      this.callback = callback;
      this.connected = false;
      this.observeCalls = [];
      observers.push(this);
    }
    observe(target, options) {
      this.connected = true;
      this.observeCalls.push({ target, options });
    }
    disconnect() { this.connected = false; }
  }

  class FakeResponse {
    constructor(body) { this.body = body; }
    async json() { return JSON.parse(this.body); }
    async text() { return this.body; }
  }

  const documentElement = new FakeElement();
  const document = {
    documentElement,
    addEventListener(name, callback) { documentListeners.set(name, callback); },
    querySelector(selector) { return selectorResults.get(selector)?.[0] ?? null; },
    querySelectorAll(selector) { return selectorResults.get(selector) ?? []; }
  };
  const sandbox = {
    console,
    document,
    HTMLElement: FakeElement,
    location: { hostname, href: `https://${hostname}/watch?v=test` },
    MutationObserver: FakeMutationObserver,
    requestAnimationFrame(callback) { frames.push(callback); },
    Response: FakeResponse,
    URL,
    fetch: async (input) => new FakeResponse(JSON.stringify({
      endpoint: String(input),
      adPlacements: [{ id: "ad" }],
      streamingData: { formats: [{ itag: 18 }] }
    })),
    addEventListener(name, callback) { windowListeners.set(name, callback); }
  };
  sandbox.window = sandbox;
  sandbox.top = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(source, sandbox, { filename: "youtube-player-protection.js" });
  return { sandbox, selectorResults, frames, FakeElement, observers, windowListeners, documentListeners };
}

test("native main-world hook is exact-site bounded", () => {
  const wrong = makeHarness("youtube.example");
  assert.equal(wrong.sandbox.__zsecYoutubeProtection, undefined);

  const correct = makeHarness();
  assert.equal(correct.sandbox.__zsecYoutubeProtection.loaded, true);
  assert.equal(correct.sandbox.__zsecYoutubeProtection.version, 1);
});

test("prunes ad fields from initial and parsed YouTube player data", () => {
  const harness = makeHarness();
  vm.runInContext(
    "ytInitialPlayerResponse = {adPlacements:[1], playerAds:[2], streamingData:{formats:[{itag:18}]}}",
    harness.sandbox
  );
  const initial = vm.runInContext("ytInitialPlayerResponse", harness.sandbox);
  assert.equal("adPlacements" in initial, false);
  assert.equal("playerAds" in initial, false);
  assert.equal(initial.streamingData.formats[0].itag, 18);

  const parsed = vm.runInContext(
    `JSON.parse('${JSON.stringify({ adSlots: [1], videoDetails: { videoId: "ok" } })}')`,
    harness.sandbox
  );
  assert.equal("adSlots" in parsed, false);
  assert.equal(parsed.videoDetails.videoId, "ok");
  assert.ok(harness.sandbox.__zsecYoutubeProtection.removedFields >= 3);
});

test("sanitizes exact player fetches without changing ordinary responses", async () => {
  const harness = makeHarness();
  const player = await harness.sandbox.fetch("/youtubei/v1/player");
  const playerData = await player.json();
  assert.equal("adPlacements" in playerData, false);
  assert.equal(playerData.streamingData.formats[0].itag, 18);

  const ordinary = await harness.sandbox.fetch("/youtubei/v1/browse");
  const ordinaryData = await ordinary.json();
  assert.equal(ordinaryData.adPlacements[0].id, "ad");
});

test("hides bounded ad containers and uses a visible skip control once", () => {
  const harness = makeHarness();
  const container = new harness.FakeElement();
  const skip = new harness.FakeElement();
  harness.selectorResults.set("#player-ads", [container]);
  harness.selectorResults.set(".ytp-ad-skip-button-modern", [skip]);
  harness.frames.shift()();
  assert.equal(container.dataset.zsecAdHidden, "true");
  assert.equal(skip.clickCount, 1);
  assert.equal(harness.sandbox.__zsecYoutubeProtection.hiddenContainers, 1);
  assert.equal(harness.sandbox.__zsecYoutubeProtection.skipControlsUsed, 1);
});

test("native skip ignores hidden duplicates and observes availability changes", () => {
  const harness = makeHarness();
  const hidden = new harness.FakeElement();
  hidden.offsetParent = null;
  const skip = new harness.FakeElement();
  skip.disabled = true;
  harness.selectorResults.set(".ytp-ad-skip-button-modern", [hidden, skip]);
  harness.frames.shift()();
  assert.equal(skip.clickCount, 0);
  const options = harness.observers[0].observeCalls[0].options;
  assert.equal(options.attributes, true);
  assert.ok(options.attributeFilter.includes("disabled"));
  skip.disabled = false;
  harness.observers[0].callback([{ type: "attributes", attributeName: "disabled" }]);
  harness.frames.shift()();
  assert.equal(skip.clickCount, 1);
  assert.equal(hidden.clickCount, 0);
  harness.observers[0].callback([]);
  harness.frames.shift()();
  assert.equal(skip.clickCount, 1);
});

test("native skip candidate work is capped", () => {
  const harness = makeHarness();
  const controls = Array.from({ length: 33 }, () => new harness.FakeElement());
  for (const control of controls.slice(0, 32)) control.offsetParent = null;
  harness.selectorResults.set(".ytp-ad-skip-button-modern", controls);
  harness.frames.shift()();
  assert.equal(controls[32].clickCount, 0);
});

test("native cleanup stops hidden page callbacks and resumes repeated BFCache restores", () => {
  const harness = makeHarness();
  const skip = new harness.FakeElement();
  harness.selectorResults.set(".ytp-ad-skip-button-modern", [skip]);
  // The initial queued frame must not click after pagehide.
  harness.windowListeners.get("pagehide")();
  harness.frames.shift()();
  assert.equal(skip.clickCount, 0);
  assert.equal(harness.observers[0].connected, false);
  harness.documentListeners.get("yt-navigate-finish")();
  assert.equal(harness.frames.length, 0);
  harness.windowListeners.get("pageshow")({ persisted: false });
  assert.equal(harness.observers[0].connected, false);
  for (let cycle = 0; cycle < 2; cycle += 1) {
    harness.windowListeners.get("pageshow")({ persisted: true });
    assert.equal(harness.observers[0].connected, true);
    harness.frames.shift()();
    assert.equal(skip.clickCount, cycle + 1);
    harness.windowListeners.get("pagehide")();
    assert.equal(harness.observers[0].connected, false);
  }
});

test("contains no remote code, telemetry, playback seeking, or unbounded polling", () => {
  for (const pattern of [
    /\.currentTime\s*=/,
    /\.playbackRate\s*=/,
    /\.muted\s*=/,
    /\bsetInterval\s*\(/,
    /\bsendBeacon\s*\(/,
    /new\s+Function\s*\(/,
    /\beval\s*\(/
  ]) {
    assert.doesNotMatch(source, pattern);
  }
});
