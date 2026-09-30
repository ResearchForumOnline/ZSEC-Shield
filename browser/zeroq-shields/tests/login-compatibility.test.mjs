import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import {
  LOGIN_COMPATIBILITY_PRIORITY,
  buildLoginCompatibilityRules,
  exactHttpsHostPattern,
  loginCompatibilityRuleIds
} from "../src/login-compatibility.js";
import { HIGH_RISK_RULE_PRIORITY } from "../src/high-risk-browsing.js";
import { normalizeSettings } from "../src/policy.js";

const rules = buildLoginCompatibilityRules();
const domainMatches = (host, domain) => host === domain || host.endsWith("." + domain);
function matches(rule, url, initiator, type = "script") {
  const condition = rule.condition;
  const host = new URL(url).hostname;
  const source = initiator ? new URL(initiator).hostname : null;
  return condition.resourceTypes.includes(type) &&
    (!condition.regexFilter || new RegExp(condition.regexFilter).test(url)) &&
    (!condition.requestDomains || condition.requestDomains.some((domain) => domainMatches(host, domain))) &&
    (!condition.initiatorDomains || source && condition.initiatorDomains.some((domain) => domainMatches(source, domain))) &&
    (!source || !condition.excludedInitiatorDomains?.some((domain) => domainMatches(source, domain)));
}
const allowed = (...request) => rules.some((rule) => matches(rule, ...request));

test("popular functional login and CDN requests receive scoped compatibility", () => {
  for (const [target, source] of [
    ["accounts.google.com", "www.google.com"],
    ["www.gstatic.com", "accounts.google.com"],
    ["auth.openai.com", "chatgpt.com"],
    ["challenges.cloudflare.com", "auth.openai.com"],
    ["accounts.google.com", "chatgpt.com"],
    ["cdn.oaistatic.com", "chatgpt.com"],
    ["scontent.xx.fbcdn.net", "www.facebook.com"],
    ["connect.facebook.net", "www.facebook.com"],
    ["login.microsoftonline.com", "www.office.com"],
    ["github.githubassets.com", "github.com"],
    ["appleid.apple.com", "www.icloud.com"]
  ]) {
    assert.equal(allowed(`https://${target}/login`, `https://${source}/`), true, `${source} to ${target}`);
  }
});

test("navigation to exact first-party authentication hosts survives ad-list false positives", () => {
  for (const host of ["accounts.google.com", "auth.openai.com", "www.facebook.com", "login.microsoftonline.com", "github.com", "appleid.apple.com"]) {
    assert.equal(allowed(`https://${host}/login?state=kept`, "https://unrelated.example/", "main_frame"), true);
  }
  assert.equal(allowed("https://www.gstatic.com/script.js", "https://unrelated.example/", "main_frame"), false);
});

test("host boundary rejects suffix spoofs, URL userinfo, insecure schemes and nonstandard ports", () => {
  const pattern = new RegExp(exactHttpsHostPattern("auth.openai.com"));
  assert.equal(pattern.test("https://auth.openai.com:443/login"), true);
  for (const url of [
    "https://auth.openai.com.evil.example/login", "https://evil-auth.openai.com/login",
    "https://auth.openai.com@evil.example/login", "http://auth.openai.com/login",
    "https://auth.openai.com:8443/login"
  ]) assert.equal(pattern.test(url), false, url);
  assert.equal(allowed("https://auth.openai.com/login", "https://chatgpt.com.evil.example/"), false);
});

test("third-party advertising and trackers remain filtered, including famous-site widgets elsewhere", () => {
  for (const source of ["chatgpt.com", "www.facebook.com", "www.google.com", "unrelated.example"]) {
    for (const target of ["doubleclick.net", "googlesyndication.com", "googleadservices.com", "google-analytics.com", "segment.io", "sentry.io"]) {
      assert.equal(allowed(`https://${target}/tracker`, `https://${source}/`), false);
    }
  }
  assert.equal(allowed("https://connect.facebook.net/en_US/fbevents.js", "https://unrelated.example/"), false);
  assert.equal(allowed("https://cdn.oaistatic.com/a.js", "https://unrelated.example/"), false);
});

test("variable CDN resources require HTTPS and the standard port", () => {
  for (const [cdn, source] of [["scontent.xx.fbcdn.net", "www.facebook.com"], ["files.oaiusercontent.com", "chatgpt.com"]]) {
    assert.equal(allowed(`https://${cdn}:443/asset`, `https://${source}/`), true);
    for (const url of [`http://${cdn}/asset`, `https://${cdn}:8443/asset`, `https://${cdn}.evil.example/asset`, `https://${cdn}@evil.example/asset`]) {
      assert.equal(allowed(url, `https://${source}/`), false, url);
    }
  }
});

test("YouTube and embedded YouTube gain no background resource whitelist", () => {
  for (const source of ["www.youtube.com", "m.youtube.com", "youtube.com", "www.youtube-nocookie.com"]) {
    for (const target of ["accounts.google.com", "www.gstatic.com", "www.googleapis.com", "doubleclick.net", "www.youtube.com"]) {
      for (const type of ["script", "xmlhttprequest", "sub_frame"]) {
        assert.equal(allowed(`https://${target}/pagead/ad_break`, `https://${source}/watch`, type), false);
      }
    }
  }
  assert.equal(allowed("https://www.youtube.com/watch?v=normal", undefined, "main_frame"), false);
});

test("compatibility is bounded, master-gated and cannot override High-Risk Browsing", () => {
  assert.equal(buildLoginCompatibilityRules(false).length, 0);
  assert.ok(rules.length > 0 && rules.length < 200);
  assert.equal(new Set(loginCompatibilityRuleIds()).size, rules.length);
  assert.ok(rules.every((rule) => rule.action.type === "allow" && rule.priority === LOGIN_COMPATIBILITY_PRIORITY));
  assert.ok(LOGIN_COMPATIBILITY_PRIORITY > 50 && LOGIN_COMPATIBILITY_PRIORITY < HIGH_RISK_RULE_PRIORITY);
  const existing = { protectionEnabled: true, highRiskMode: true, youtubeCleanup: false, pausedSites: ["my.example"] };
  assert.deepEqual(normalizeSettings(existing), existing);
});

test("worker installs and verifies built-in rules without changing stored user preferences", async () => {
  const worker = await readFile(new URL("../src/service-worker.js", import.meta.url), "utf8");
  assert.match(worker, /buildLoginCompatibilityRules\(settings\.protectionEnabled\)/);
  assert.match(worker, /removeRuleIds:.*loginCompatibilityRuleIds\(\)/);
  assert.match(worker, /verifyDnrRuntime\([\s\S]*dynamicRulesFor\(candidate\)/);
});
