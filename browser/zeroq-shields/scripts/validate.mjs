import { readFile, readdir } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const manifest = JSON.parse(await readFile(join(root, "manifest.json"), "utf8"));
const blockingRules = JSON.parse(await readFile(join(root, "rules", "privacy.json"), "utf8"));
const linkRules = JSON.parse(await readFile(join(root, "rules", "link-cleaning.json"), "utf8"));
const popup = await readFile(join(root, "popup", "index.html"), "utf8");
const serviceWorker = await readFile(join(root, "src", "service-worker.js"), "utf8");
const totalRules = blockingRules.length + linkRules.length;

if (manifest.manifest_version !== 3) throw new Error("Manifest V3 is required");
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
if (!popup.includes("https://talktoai.org/zero-browser/privacy/")) throw new Error("Privacy URL missing");
if (!serviceWorker.includes("runtimeHealth")) throw new Error("Runtime health reporting missing");
if (serviceWorker.includes(".catch(() => undefined)")) throw new Error("Initialization errors are hidden");
if (!serviceWorker.includes('"privacy_rules", "link_cleanup"')) throw new Error("Protection toggle does not cover both rulesets");

const jsFiles = (await readdir(join(root, "src"))).filter((name) => name.endsWith(".js"));
for (const name of jsFiles) {
  const source = await readFile(join(root, "src", name), "utf8");
  if (/\beval\s*\(|new\s+Function\s*\(/.test(source)) throw new Error(`Dynamic code forbidden: ${name}`);
  if (/https?:\/\//.test(source)) throw new Error(`Remote endpoint/code reference forbidden in source: ${name}`);
}

console.log(`Validated ZeroQ Shields MV3: ${blockingRules.length} blockers, ${linkRules.length} link cleaners, ${jsFiles.length} source modules.`);
