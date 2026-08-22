export const UNCHECKED_HEALTH = Object.freeze({
  ok: false,
  state: "unchecked",
  error: "Local filtering has not been verified",
  diagnostic: "health_record_absent_or_stale",
  details: null
});

export function normalizeContextDomain(value) {
  if (typeof value !== "string") return null;
  const domain = value.trim().toLowerCase().replace(/^\.+|\.+$/g, "");
  if (!domain || domain.length > 253 || domain === "localhost" || domain.includes("..")) return null;
  if (!/^[a-z0-9.-]+$/.test(domain)) return null;
  const labels = domain.split(".");
  if (labels.length < 2 || labels.some(
    (label) => !label || label.length > 63 || label.startsWith("-") || label.endsWith("-")
  )) return null;
  return domain;
}

export function healthPresentation(settings, health = UNCHECKED_HEALTH) {
  const unavailable = health?.ok !== true;
  const details = health?.details;
  let status;
  if (unavailable) status = health?.state === "unchecked" ? "Verifying local filtering…" : "Filtering state unavailable";
  else if (!settings.protectionEnabled) status = "ZSEC rules are off";
  else if (settings.highRiskMode) status = "High-Risk mode is on";
  else status = health.state === "verified_limited" ? "ZSEC rules are on · limited verification" : "ZSEC rules are verified";

  let coverage;
  if (unavailable) coverage = "Coverage verification did not complete";
  else if (details?.filteringMode === "on") {
    const packaged = Number.isSafeInteger(details.packagedStaticRuleCount)
      ? details.packagedStaticRuleCount.toLocaleString("en-GB")
      : "Unknown";
    const representative = details.representativeMatchStatus === "verified"
      ? `${details.representativeMatches.length} representative checks passed`
      : "representative checks unavailable";
    coverage = `${packaged} packaged rules · ${details.regexRulesVerified} regex checks · ${representative}`;
  } else {
    coverage = "Network filtering is intentionally off";
  }

  const message = unavailable
    ? health?.diagnostic
      ? `${health.error || "Extension initialization failed"} (${health.diagnostic})`
      : health?.error || "Extension initialization failed"
    : "";
  return { unavailable, status, coverage, message };
}
