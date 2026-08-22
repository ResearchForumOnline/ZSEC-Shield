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
    constructor(callback) { this.callback = callback; }
    observe() {}
    disconnect() {}
  }

  class FakeResponse {
    constructor(body) { this.body = body; }
    async json() { return JSON.parse(this.body); }
    async text() { return this.body; }
  }

  const documentElement = new FakeElement();
  const document = {
    documentElement,
    addEventListener() {},
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
    addEventListener() {}
  };
  sandbox.window = sandbox;
  sandbox.top = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(source, sandbox, { filename: "youtube-player-protection.js" });
  return { sandbox, selectorResults, frames, FakeElement };
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
