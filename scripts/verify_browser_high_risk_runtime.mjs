#!/usr/bin/env node

// Disposable Chromium integration check for ZSEC Browser Shields High-Risk Browsing.
// It uses a fresh browser profile and local-only HTTP endpoints. No normal user
// profile, browsing data, or external site is touched.

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { createServer as createNetServer } from "node:net";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const extension = resolve(root, "browser", "zeroq-shields");
const browserCandidates = [
  "C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe",
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"
];

function delay(milliseconds) {
  return new Promise((resolveDelay) => setTimeout(resolveDelay, milliseconds));
}

async function availablePort() {
  const server = createNetServer();
  await new Promise((resolveListen, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolveListen);
  });
  const address = server.address();
  assert.ok(address && typeof address === "object");
  const port = address.port;
  await new Promise((resolveClose) => server.close(resolveClose));
  return port;
}

async function waitForJson(url, timeoutMilliseconds = 20_000) {
  const deadline = Date.now() + timeoutMilliseconds;
  let lastError;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url);
      if (response.ok) return response.json();
      lastError = new Error(`HTTP ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    await delay(150);
  }
  throw new Error(`Timed out waiting for ${url}: ${lastError?.message || "no response"}`);
}

class CdpSession {
  constructor(socket) {
    this.socket = socket;
    this.nextId = 1;
    this.pending = new Map();
    socket.addEventListener("message", (event) => {
      const message = JSON.parse(String(event.data));
      if (!message.id || !this.pending.has(message.id)) return;
      const { resolveMessage, rejectMessage } = this.pending.get(message.id);
      this.pending.delete(message.id);
      if (message.error) rejectMessage(new Error(JSON.stringify(message.error)));
      else resolveMessage(message.result || {});
    });
    socket.addEventListener("close", () => {
      for (const { rejectMessage } of this.pending.values()) {
        rejectMessage(new Error("Chrome DevTools connection closed"));
      }
      this.pending.clear();
    });
  }

  static async connect(url) {
    const socket = new WebSocket(url);
    await new Promise((resolveOpen, reject) => {
      socket.addEventListener("open", resolveOpen, { once: true });
      socket.addEventListener("error", reject, { once: true });
    });
    return new CdpSession(socket);
  }

  send(method, params = {}) {
    const id = this.nextId++;
    return new Promise((resolveMessage, rejectMessage) => {
      this.pending.set(id, { resolveMessage, rejectMessage });
      this.socket.send(JSON.stringify({ id, method, params }));
    });
  }

  close() {
    this.socket.close();
  }
}

async function evaluate(session, expression) {
  const result = await session.send("Runtime.evaluate", {
    expression,
    awaitPromise: true,
    returnByValue: true,
    userGesture: true
  });
  if (result.exceptionDetails) {
    throw new Error(`Runtime evaluation failed: ${JSON.stringify(result.exceptionDetails)}`);
  }
  return result.result?.value;
}

async function waitFor(check, description, timeoutMilliseconds = 8_000) {
  const deadline = Date.now() + timeoutMilliseconds;
  let value;
  while (Date.now() < deadline) {
    value = await check();
    if (value) return value;
    await delay(100);
  }
  throw new Error(`Timed out waiting for ${description}`);
}

async function findBrowser(explicitPath) {
  const { access } = await import("node:fs/promises");
  const candidates = explicitPath ? [resolve(explicitPath)] : browserCandidates;
  for (const candidate of candidates) {
    try {
      await access(candidate);
      return candidate;
    } catch {
      // Continue to the next known Chromium-family browser.
    }
  }
  throw new Error("No supported Chromium-family browser executable was found");
}

async function main() {
  const browser = await findBrowser(process.argv[2]);
  const profile = await mkdtemp(resolve(tmpdir(), "zsec-browser-runtime-"));
  const debugPort = await availablePort();
  const requests = [];

  const server = createServer((request, response) => {
    requests.push(request.url || "");
    if ((request.url || "").startsWith("/payload.js")) {
      const token = new URL(request.url, "http://localhost").searchParams.get("token");
      response.writeHead(200, { "Content-Type": "application/javascript", "Cache-Control": "no-store" });
      response.end(`globalThis.__zsecLoaded ??= {}; globalThis.__zsecLoaded[${JSON.stringify(token)}] = true;`);
      return;
    }
    response.writeHead(200, { "Content-Type": "text/html", "Cache-Control": "no-store" });
    response.end("<!doctype html><title>ZSEC runtime test</title><h1>ZSEC runtime test</h1>");
  });
  await new Promise((resolveListen, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolveListen);
  });
  const address = server.address();
  assert.ok(address && typeof address === "object");
  const testPort = address.port;

  const child = spawn(browser, [
    "--headless=new",
    "--disable-gpu",
    "--no-first-run",
    "--no-default-browser-check",
    "--remote-allow-origins=*",
    `--remote-debugging-port=${debugPort}`,
    `--user-data-dir=${profile}`,
    `--disable-extensions-except=${extension}`,
    `--load-extension=${extension}`,
    "about:blank"
  ], { stdio: ["ignore", "pipe", "pipe"], windowsHide: true });

  let stderr = "";
  child.stderr.on("data", (chunk) => {
    stderr += String(chunk);
  });

  let worker;
  let controller;
  let page;
  try {
    await waitForJson(`http://127.0.0.1:${debugPort}/json/version`);
    const targets = await waitFor(async () => {
      const listed = await waitForJson(`http://127.0.0.1:${debugPort}/json/list`, 2_000);
      const serviceWorker = listed.find(
        (target) => target.type === "service_worker" && target.url.endsWith("/src/service-worker.js")
      );
      const pageTarget = listed.find((target) => target.type === "page");
      return serviceWorker && pageTarget ? { serviceWorker, pageTarget } : null;
    }, "the unpacked ZSEC extension service worker and test page", 15_000);

    worker = await CdpSession.connect(targets.serviceWorker.webSocketDebuggerUrl);
    page = await CdpSession.connect(targets.pageTarget.webSocketDebuggerUrl);
    await Promise.all([worker.send("Runtime.enable"), page.send("Runtime.enable"), page.send("Page.enable")]);

    const serviceWorkerUrl = new URL(targets.serviceWorker.url);
    const extensionOrigin = `${serviceWorkerUrl.protocol}//${serviceWorkerUrl.host}`;
    const controllerResponse = await fetch(
      `http://127.0.0.1:${debugPort}/json/new?${encodeURIComponent(`${extensionOrigin}/popup/index.html`)}`,
      { method: "PUT" }
    );
    assert.equal(controllerResponse.ok, true);
    const controllerTarget = await controllerResponse.json();
    controller = await CdpSession.connect(controllerTarget.webSocketDebuggerUrl);
    await controller.send("Runtime.enable");
    await waitFor(
      () => evaluate(controller, "typeof chrome?.runtime?.sendMessage === 'function'"),
      "extension controller page"
    );

    const setHighRisk = async (enabled) => evaluate(
      controller,
      `new Promise((resolve) => chrome.runtime.sendMessage({type: "setHighRiskMode", enabled: ${enabled}}, resolve))`
    );
    const statusOff = await setHighRisk(false);
    assert.equal(statusOff.ok, true);

    const pageUrl = `http://127.0.0.1:${testPort}/page`;
    const navigationOff = await page.send("Page.navigate", { url: pageUrl });
    assert.equal(navigationOff.errorText, undefined);
    await waitFor(() => evaluate(page, "document.title === 'ZSEC runtime test'"), "local test page");

    const loadScript = (token) => evaluate(page, `new Promise((resolve) => {
      globalThis.__zsecLoaded ??= {};
      const script = document.createElement("script");
      script.src = "http://localhost:${testPort}/payload.js?token=${token}";
      script.onload = () => resolve({event: "load", loaded: globalThis.__zsecLoaded["${token}"] === true});
      script.onerror = () => resolve({event: "error", loaded: globalThis.__zsecLoaded["${token}"] === true});
      document.head.append(script);
    })`);

    const allowed = await loadScript("allowed");
    assert.deepEqual(allowed, { event: "load", loaded: true });
    assert.ok(requests.some((path) => path.includes("token=allowed")));

    const statusOn = await setHighRisk(true);
    assert.equal(statusOn.ok, true);
    const rules = await evaluate(controller, "chrome.declarativeNetRequest.getDynamicRules()");
    assert.deepEqual(rules.map((rule) => rule.id).sort((a, b) => a - b), [200000, 200001]);

    const blocked = await loadScript("blocked");
    assert.deepEqual(blocked, { event: "error", loaded: false });
    assert.ok(!requests.some((path) => path.includes("token=blocked")));

    const blockedNavigation = await page.send("Page.navigate", {
      url: `http://127.0.0.1:${testPort}/blocked-navigation`
    });
    assert.equal(blockedNavigation.errorText, "net::ERR_BLOCKED_BY_CLIENT");
    assert.ok(!requests.includes("/blocked-navigation"));

    const statusRestored = await setHighRisk(false);
    assert.equal(statusRestored.ok, true);
    const restoredRules = await evaluate(controller, "chrome.declarativeNetRequest.getDynamicRules()");
    assert.deepEqual(restoredRules, []);
    const navigationRestored = await page.send("Page.navigate", {
      url: `http://127.0.0.1:${testPort}/restored-navigation`
    });
    assert.equal(navigationRestored.errorText, undefined);
    await waitFor(() => requests.includes("/restored-navigation"), "restored HTTP navigation");

    console.log(JSON.stringify({
      browser,
      extensionVersion: "0.4.0",
      highRiskRulesInstalled: [200000, 200001],
      thirdPartyScript: "blocked-before-server",
      plaintextMainFrame: "blocked-before-server",
      explicitDisableRestoresNavigation: true,
      isolatedProfile: profile
    }, null, 2));
  } catch (error) {
    const detail = stderr.trim().slice(-2_000);
    throw new Error(`${error.message}${detail ? `\nBrowser stderr:\n${detail}` : ""}`);
  } finally {
    page?.close();
    controller?.close();
    worker?.close();
    child.kill();
    await new Promise((resolveExit) => {
      if (child.exitCode !== null) resolveExit();
      else {
        child.once("exit", resolveExit);
        setTimeout(resolveExit, 3_000);
      }
    });
    await new Promise((resolveClose) => server.close(resolveClose));
    await rm(profile, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack : String(error));
  process.exitCode = 1;
});
