import { readFile, readdir } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  HIGH_RISK_RULE_PRIORITY,
  buildHighRiskRules,
  buildHighRiskRulesForSettings,
  highRiskRuleIds
} from "../src/high-risk-browsing.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const manifest = JSON.parse(await readFile(join(root, "manifest.json"), "utf8"));
const packageJson = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
const blockingRules = JSON.parse(await readFile(join(root, "rules", "privacy.json"), "utf8"));
const linkRules = JSON.parse(await readFile(join(root, "rules", "link-cleaning.json"), "utf8"));
const popup = await readFile(join(root, "popup", "index.html"), "utf8");
const popupScript = await readFile(join(root, "popup", "popup.js"), "utf8");
const serviceWorker = await readFile(join(root, "src", "service-worker.js"), "utf8");
const totalRules = blockingRules.length + linkRules.length;

if (manifest.manifest_version !== 3) throw new Error("Manifest V3 is required");
if (manifest.name !== "ZSEC Browser Shields" || manifest.short_name !== "ZSEC Shields") {
  throw new Error("Public extension branding is stale");
}
if (manifest.version !== "0.4.1" || packageJson.version !== manifest.version) {
  throw new Error("Manifest/package release version must match the reviewed 0.4.1 release");
}
const resources = manifest.declarative_net_request?.rule_resources || [];
if (resources.length !== 2) throw new Error("Expected blocking and link-cleaning rulesets");
if (!resources.every((resource) => resource.enabled === true)) throw new Error("Protection rulesets must start enabled");
if (manifest.permissions.includes("webRequestBlocking")) throw new Error("MV2 blocking permission forbidden");
for (const [name, rules] of [["blocking", blockingRules], ["link cleaning", linkRules]]) {
  if (new Set(rules.map((rule) => rule.id)).size !== rules.length) throw new Error(`${name} rule IDs must be unique`);
  if (rules.some((rule) => rule.condition?.regexFilter)) throw new Error(`${name} regex rules require separate review`);
}
if (blockingRules.some((rule) => rule.action?.type !== "block")) throw new Error("Blocking ruleset must only block");
if (linkRules.some((rule) => rule.action?.type !== "redirect")) throw new Error("Link ruleset must only redirect");
if (linkRules.some((rule) => rule.condition?.resourceTypes?.join() !== "main_frame")) throw new Error("Link cleaning must be limited to top-level navigation");
if (linkRules.some((rule) => !rule.action?.redirect?.transform?.queryTransform?.removeParams?.length)) throw new Error("Link rules must only remove declared parameters");
if (!popup.includes(`${totalRules} bundled protection rules`)) throw new Error("Popup rule count is stale");
if (!popup.includes("ZSEC Browser") || popup.includes("ZeroQ Shields")) throw new Error("Popup branding is stale");
if (!popup.includes("https://talktoai.org/zero-browser/privacy/")) throw new Error("Privacy URL missing");
if (!serviceWorker.includes("runtimeHealth")) throw new Error("Runtime health reporting missing");
if (serviceWorker.includes(".catch(() => undefined)")) throw new Error("Initialization errors are hidden");
if (!serviceWorker.includes('"privacy_rules", "link_cleanup"')) throw new Error("Protection toggle does not cover both rulesets");
if (!serviceWorker.includes("buildHighRiskRulesForSettings(normalized)")) throw new Error("High-risk rules are not gated by normalized local settings");
if (!serviceWorker.includes("buildPauseRules(normalized.protectionEnabled ? normalized.pausedSites : [])")) throw new Error("Pause rules are not gated by the master protection control");
if (!serviceWorker.includes('highRiskActive ? "HIGH"')) throw new Error("High-risk badge state is not explicit");
if (!serviceWorker.includes('message.type === "setHighRiskMode"')) throw new Error("High-risk control message missing");
if (!popup.includes('id="high-risk"') || !popup.includes("may break sites")) throw new Error("High-risk opt-in/breakage disclosure missing");
if (!popup.includes('id="pause-site"')) throw new Error("Site-pause control missing");
if (!popupScript.includes("settings.protectionEnabled && settings.highRiskMode")) throw new Error("Popup high-risk status is not master-gated");
if (!popupScript.includes("settings.highRiskMode;")) throw new Error("Site pause is not disabled during High-Risk Browsing");
if (!popupScript.includes("Unavailable while High-Risk Browsing is active")) throw new Error("Site-pause override explanation missing");

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

console.log(`Validated ZSEC Browser Shields MV3: ${blockingRules.length} blockers, ${linkRules.length} link cleaners, ${jsFiles.length} source modules.`);
