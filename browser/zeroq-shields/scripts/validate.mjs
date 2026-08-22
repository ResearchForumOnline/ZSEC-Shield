import { readFile, readdir } from "node:fs/promises";
import { createHash } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  HIGH_RISK_RULE_PRIORITY,
  buildHighRiskRules,
  buildHighRiskRulesForSettings,
  highRiskRuleIds
} from "../src/high-risk-browsing.js";
import {
  EXPECTED_RULESET_IDS,
  PACKAGED_STATIC_RULE_COUNT,
  REQUIRED_REGEX_RULES,
  RUNTIME_HEALTH_SCHEMA,
  RUNTIME_POLICY_REVISION
} from "../src/runtime-health.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const manifest = JSON.parse(await readFile(join(root, "manifest.json"), "utf8"));
const packageJson = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
const blockingRules = JSON.parse(await readFile(join(root, "rules", "privacy.json"), "utf8"));
const linkRules = JSON.parse(await readFile(join(root, "rules", "link-cleaning.json"), "utf8"));
const easyListBytes = await readFile(join(root, "rules", "easylist.json"));
const easyListRules = JSON.parse(easyListBytes.toString("utf8"));
const easyListLock = JSON.parse(await readFile(join(root, "easylist.lock.json"), "utf8"));
const easyListProvenance = JSON.parse(await readFile(join(root, "third_party", "easylist-provenance.json"), "utf8"));
const easyListSource = await readFile(join(root, "third_party", "easylist-20260817.txt"));
const popup = await readFile(join(root, "popup", "index.html"), "utf8");
const popupScript = await readFile(join(root, "popup", "popup.js"), "utf8");
const popupState = await readFile(join(root, "src", "popup-state.js"), "utf8");
const runtimeHealth = await readFile(join(root, "src", "runtime-health.js"), "utf8");
const serviceWorker = await readFile(join(root, "src", "service-worker.js"), "utf8");
const youtubeCosmeticRules = await readFile(join(root, "src", "youtube-cosmetic-rules.js"), "utf8");
const youtubeCleanup = await readFile(join(root, "src", "youtube-cleanup.js"), "utf8");
const totalRules = blockingRules.length + linkRules.length + easyListRules.length;

if (manifest.manifest_version !== 3) throw new Error("Manifest V3 is required");
if (manifest.name !== "ZSEC Browser Shields" || manifest.short_name !== "ZSEC Shields") {
  throw new Error("Public extension branding is stale");
}
if (manifest.version !== "0.5.2" || packageJson.version !== manifest.version) {
  throw new Error("Manifest/package release version must match the reviewed 0.5.2 release");
}
const resources = manifest.declarative_net_request?.rule_resources || [];
if (resources.length !== 3) throw new Error("Expected EasyList, privacy and link-cleaning rulesets");
if (resources.map((resource) => resource.id).join() !== "privacy_rules,link_cleanup,easylist_ads") {
  throw new Error("Static ruleset identity or order drifted");
}
if (!resources.every((resource) => resource.enabled === true)) throw new Error("Protection rulesets must start enabled");
if (manifest.permissions.includes("webRequestBlocking")) throw new Error("MV2 blocking permission forbidden");
for (const [name, rules] of [["blocking", blockingRules], ["link cleaning", linkRules]]) {
  if (new Set(rules.map((rule) => rule.id)).size !== rules.length) throw new Error(`${name} rule IDs must be unique`);
  if (rules.some((rule) => rule.condition?.regexFilter)) throw new Error(`${name} regex rules require separate review`);
}
if (easyListRules.length !== 49464) throw new Error("Pinned EasyList DNR rule count drifted");
const staticIds = [...blockingRules, ...linkRules, ...easyListRules].map((rule) => rule.id);
if (new Set(staticIds).size !== staticIds.length) throw new Error("Static DNR rule IDs overlap");
if (blockingRules.some((rule) => rule.priority !== 50)) throw new Error("ZSEC privacy priority drifted");
if (linkRules.some((rule) => rule.priority !== 40)) throw new Error("Link-cleaning priority drifted");
if (easyListRules.some((rule) => ![10, 20, 21].includes(rule.priority))) {
  throw new Error("EasyList rules escaped their reviewed priority band");
}
const easyListMaximumPriority = easyListRules.reduce(
  (maximum, rule) => Math.max(maximum, rule.priority),
  0
);
const privacyMinimumPriority = blockingRules.reduce(
  (minimum, rule) => Math.min(minimum, rule.priority),
  Number.MAX_SAFE_INTEGER
);
if (easyListMaximumPriority >= privacyMinimumPriority) {
  throw new Error("EasyList exceptions could override focused ZSEC privacy blocks");
}
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
if (sha256(easyListBytes) !== easyListLock.ruleset.output_sha256 ||
    easyListBytes.length !== easyListLock.ruleset.output_bytes) {
  throw new Error("EasyList generated rules do not match the exact lock");
}
if (sha256(easyListSource) !== easyListLock.ruleset.source_sha256 ||
    easyListSource.length !== easyListLock.ruleset.source_bytes) {
  throw new Error("EasyList retained source does not match the exact lock");
}
if (easyListLock.ruleset.acceptable_ads_included !== false ||
    easyListLock.policy.acceptable_ads_default !== false ||
    easyListProvenance.policy.acceptable_ads_included !== false ||
    easyListSource.toString("utf8").includes("! Title: Allow nonintrusive advertising")) {
  throw new Error("Acceptable Ads must not be bundled or enabled");
}
if (blockingRules.some((rule) => rule.action?.type !== "block")) throw new Error("Blocking ruleset must only block");
if (linkRules.some((rule) => rule.action?.type !== "redirect")) throw new Error("Link ruleset must only redirect");
if (linkRules.some((rule) => rule.condition?.resourceTypes?.join() !== "main_frame")) throw new Error("Link cleaning must be limited to top-level navigation");
if (linkRules.some((rule) => !rule.action?.redirect?.transform?.queryTransform?.removeParams?.length)) throw new Error("Link rules must only remove declared parameters");
if (PACKAGED_STATIC_RULE_COUNT !== totalRules) throw new Error("Runtime-health rule count is stale");
if (!popupState.includes('details.packagedStaticRuleCount.toLocaleString("en-GB")')) throw new Error("Popup runtime coverage count is missing");
if (!popupState.includes("health?.ok !== true")) throw new Error("Popup health must fail closed unless explicitly verified");
if (!popup.includes('<p id="status-title" class="status">Verifying local filtering…</p>')) throw new Error("Popup initial health wording is not fail closed");
for (const id of ["protection", "high-risk", "youtube"]) {
  if (!popup.includes(`<input id="${id}" type="checkbox" disabled>`)) throw new Error(`Popup ${id} control is enabled before verification`);
}
if (!popup.includes("ZSEC Browser") || popup.includes("ZeroQ Shields")) throw new Error("Popup branding is stale");
if (!popup.includes("https://talktoai.org/zero-browser/privacy/")) throw new Error("Privacy URL missing");
if (!serviceWorker.includes("runtimeHealth")) throw new Error("Runtime health reporting missing");
if (serviceWorker.includes(".catch(() => undefined)")) throw new Error("Initialization errors are hidden");
if (EXPECTED_RULESET_IDS.join() !== resources.map((resource) => resource.id).join()) throw new Error("Runtime ruleset identity is stale");
if (!serviceWorker.includes("dynamicRulesFor(candidate)")) throw new Error("Exact dynamic-rule verification is not enforced");
if (!serviceWorker.includes("enqueueOperation(respond)")) throw new Error("Settings operations are not serialized");
if (!serviceWorker.includes("health: result.health")) throw new Error("Settings responses omit committed runtime health");
if (!popupScript.includes("recoverAfterSettingFailure")) throw new Error("Popup does not reverify after a failed settings transaction");
if (!runtimeHealth.includes("testMatchOutcome")) throw new Error("Representative DNR match evidence is missing");
if (RUNTIME_HEALTH_SCHEMA !== "zsec.browser-shields.runtime-health.v3") throw new Error("Runtime health schema is stale");
if (!RUNTIME_POLICY_REVISION.includes(easyListLock.ruleset.output_sha256)) throw new Error("Runtime health is not bound to the pinned EasyList output");
const pinnedRegexRules = easyListRules.filter((rule) => rule.condition?.regexFilter);
if (pinnedRegexRules.length !== REQUIRED_REGEX_RULES.length || REQUIRED_REGEX_RULES.some((expected) => {
  const actual = pinnedRegexRules.find((rule) => rule.id === expected.id);
  return !actual || actual.condition.regexFilter !== expected.regex ||
    (actual.condition.isUrlFilterCaseSensitive === true) !== expected.isCaseSensitive;
})) {
  throw new Error("Runtime regex evidence drifted from the pinned EasyList rules");
}
if (!serviceWorker.includes("buildHighRiskRulesForSettings(settings)")) throw new Error("High-risk rules are not gated by normalized local settings");
if (!serviceWorker.includes("buildPauseRules(settings.protectionEnabled ? settings.pausedSites : [])")) throw new Error("Pause rules are not gated by the master protection control");
if (!serviceWorker.includes('highRiskActive ? "HIGH"')) throw new Error("High-risk badge state is not explicit");
if (!serviceWorker.includes('message.type === "setHighRiskMode"')) throw new Error("High-risk control message missing");
if (!popup.includes('id="high-risk"') || !popup.includes("may break sites")) throw new Error("High-risk opt-in/breakage disclosure missing");
if (!popup.includes('id="pause-site"')) throw new Error("Site-pause control missing");
if (!popupState.includes("else if (!settings.protectionEnabled)") ||
    !popupState.includes("else if (settings.highRiskMode)")) {
  throw new Error("Popup high-risk status is not master-gated");
}
if (!popupScript.includes("settings.highRiskMode;")) throw new Error("Site pause is not disabled during High-Risk Browsing");
if (!popupScript.includes("Unavailable while High-Risk Browsing is active")) throw new Error("Site-pause override explanation missing");

const youtubeForbidden = [
  [/\.currentTime\s*=/, "video seeking"],
  [/\.playbackRate\s*=/, "playback acceleration"],
  [/\.muted\s*=/, "forced muting"],
  [/\.volume\s*=/, "volume changes"],
  [/\bsetInterval\s*\(/, "unbounded polling"],
  [/\b(?:fetch|XMLHttpRequest|WebSocket|EventSource)\b/, "page/network inspection"],
  [/\bsendBeacon\s*\(/, "telemetry"],
];
const youtubeCosmeticSelectorCount = (youtubeCosmeticRules.match(/^  "/gm) || []).length;
if (youtubeCosmeticSelectorCount !== 19) {
  throw new Error("Pinned YouTube cosmetic selector count drifted");
}
if (!youtubeCosmeticRules.includes("globalThis.ZSEC_YOUTUBE_COSMETIC_SELECTORS = Object.freeze([")) {
  throw new Error("YouTube cosmetic rules are not exported as an immutable selector list");
}
for (const [pattern, behavior] of youtubeForbidden) {
  if (pattern.test(youtubeCleanup) || pattern.test(youtubeCosmeticRules)) {
    throw new Error(`YouTube assistance must not use ${behavior}`);
  }
}
if (!youtubeCleanup.includes('host !== "www.youtube.com" && host !== "m.youtube.com"')) {
  throw new Error("YouTube assistance lacks an exact-host runtime guard");
}
if (!youtubeCleanup.includes("button.getAttribute(\"aria-disabled\")")) {
  throw new Error("YouTube assistance does not reject disabled controls");
}

const highRiskRules = buildHighRiskRules(true);
if (buildHighRiskRules(false).length !== 0) throw new Error("High-risk rules must default off");
if (highRiskRules.length !== 2 || highRiskRuleIds().length !== 2) throw new Error("High-risk dynamic rule budget changed");
if (highRiskRules.some((rule) => rule.action?.type !== "block")) throw new Error("High-risk rules must only block");
if (highRiskRules.some((rule) => rule.priority !== HIGH_RISK_RULE_PRIORITY)) throw new Error("High-risk rule priority drifted");
if (HIGH_RISK_RULE_PRIORITY <= 100) throw new Error("Site pause could override High-Risk Browsing");
if (buildHighRiskRulesForSettings({ protectionEnabled: false, highRiskMode: true }).length !== 0) throw new Error("Master protection OFF leaves high-risk rules active");

const jsFiles = (await readdir(join(root, "src"))).filter((name) => name.endsWith(".js"));
for (const name of jsFiles) {
  const source = await readFile(join(root, "src", name), "utf8");
  if (/\beval\s*\(|new\s+Function\s*\(/.test(source)) throw new Error(`Dynamic code forbidden: ${name}`);
  const remoteCheckSource = name === "high-risk-browsing.js"
    ? source.replaceAll('"|http://"', '"<reviewed-local-dnr-filter>"')
    : source;
  if (/https?:\/\//.test(remoteCheckSource)) throw new Error(`Remote endpoint/code reference forbidden in source: ${name}`);
}

console.log(`Validated ZSEC Browser Shields MV3: ${easyListRules.length} EasyList rules, ${blockingRules.length} focused privacy blockers, ${linkRules.length} link cleaners, ${jsFiles.length} source modules.`);
