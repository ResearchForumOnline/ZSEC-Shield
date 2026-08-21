import { readFile, readdir } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const manifest = JSON.parse(await readFile(join(root, "manifest.json"), "utf8"));
const rules = JSON.parse(await readFile(join(root, "rules", "privacy.json"), "utf8"));

if (manifest.manifest_version !== 3) throw new Error("Manifest V3 is required");
if (!manifest.declarative_net_request?.rule_resources?.length) throw new Error("Static ruleset missing");
if (manifest.permissions.includes("webRequestBlocking")) throw new Error("MV2 blocking permission forbidden");
if (new Set(rules.map((rule) => rule.id)).size !== rules.length) throw new Error("Rule IDs must be unique");
if (rules.some((rule) => rule.action?.type !== "block")) throw new Error("Static rules must be block rules");
if (rules.some((rule) => rule.condition?.regexFilter)) throw new Error("Regex rules require separate review");

const jsFiles = (await readdir(join(root, "src"))).filter((name) => name.endsWith(".js"));
for (const name of jsFiles) {
  const source = await readFile(join(root, "src", name), "utf8");
  if (/\beval\s*\(|new\s+Function\s*\(/.test(source)) throw new Error(`Dynamic code forbidden: ${name}`);
  if (/https?:\/\//.test(source)) throw new Error(`Remote endpoint/code reference forbidden in source: ${name}`);
}

console.log(`Validated ZeroQ Shields MV3: ${rules.length} static rules, ${jsFiles.length} source modules.`);
