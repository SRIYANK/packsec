"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.checkAge = checkAge;
const SOURCE = "https://registry.npmjs.org";
async function checkAge(packageName, version, maxAgeHours) {
    const flags = [];
    const checks = [];
    const start = Date.now();
    const url = `${SOURCE}/${packageName}`;
    let meta;
    try {
        const res = await fetch(url, {
            signal: AbortSignal.timeout(5000),
            headers: { Accept: "application/json" },
        });
        if (res.status === 404) {
            const ms = Date.now() - start;
            flags.push({
                type: "phantom_dep",
                severity: "critical",
                message: `"${packageName}" does not exist in the npm registry`,
                detail: "This package was never published — possible phantom dependency attack",
            });
            checks.push({
                name: "Package Existence",
                source: url,
                passed: false,
                detail: `"${packageName}" returned 404 — not found in npm registry`,
                durationMs: ms,
            });
            return { flags, checks };
        }
        meta = (await res.json());
    }
    catch {
        checks.push({
            name: "Package Age",
            source: url,
            passed: true,
            detail: "Skipped — network unavailable (fail-open)",
            durationMs: Date.now() - start,
        });
        return { flags, checks };
    }
    const allVersions = Object.keys(meta.versions ?? {});
    const createdAt = meta.time?.created;
    if (createdAt) {
        const ageHours = (Date.now() - new Date(createdAt).getTime()) / 3_600_000;
        if (ageHours < 1) {
            flags.push({
                type: "package_age",
                severity: "critical",
                message: `"${packageName}" was created < 1 hour ago`,
                detail: `Published: ${new Date(createdAt).toUTCString()}. Extremely suspicious as a transitive dep.`,
            });
            checks.push({
                name: "Package Age",
                source: url,
                passed: false,
                detail: `Created ${new Date(createdAt).toUTCString()} (< 1 hour ago). ${allVersions.length} version(s).`,
                durationMs: Date.now() - start,
            });
        }
        else if (ageHours < maxAgeHours) {
            flags.push({
                type: "package_age",
                severity: allVersions.length === 1 ? "high" : "medium",
                message: `"${packageName}" was created ${Math.round(ageHours)}h ago`,
                detail: allVersions.length === 1
                    ? "Only one version ever published — brand new package in your install chain"
                    : `${allVersions.length} versions published in < ${maxAgeHours}h`,
            });
            checks.push({
                name: "Package Age",
                source: url,
                passed: false,
                detail: `Created ${new Date(createdAt).toUTCString()} (${Math.round(ageHours)}h ago). ${allVersions.length} version(s).`,
                durationMs: Date.now() - start,
            });
        }
        else {
            const ageDays = Math.round(ageHours / 24);
            checks.push({
                name: "Package Age",
                source: url,
                passed: true,
                detail: `Created ${new Date(createdAt).toUTCString()} (${ageDays} days ago). ${allVersions.length} version(s) published.`,
                durationMs: Date.now() - start,
            });
        }
    }
    else {
        checks.push({
            name: "Package Age",
            source: url,
            passed: true,
            detail: "No creation timestamp found in registry metadata",
            durationMs: Date.now() - start,
        });
    }
    // Version-specific age check
    const versionTime = meta.time?.[version];
    if (versionTime) {
        const versionAgeHours = (Date.now() - new Date(versionTime).getTime()) / 3_600_000;
        if (versionAgeHours < 2 && allVersions.length > 5) {
            flags.push({
                type: "package_age",
                severity: "high",
                message: `"${packageName}@${version}" was published < 2 hours ago`,
                detail: `Package exists (${allVersions.length} versions) but this specific version is brand new`,
            });
            checks.push({
                name: "Version Age",
                source: url,
                passed: false,
                detail: `Version ${version} published ${new Date(versionTime).toUTCString()} (< 2h ago) on a package with ${allVersions.length} versions`,
                durationMs: Date.now() - start,
            });
        }
        else {
            const vDays = Math.round(versionAgeHours / 24);
            checks.push({
                name: "Version Age",
                source: url,
                passed: true,
                detail: `Version ${version} published ${new Date(versionTime).toUTCString()} (${vDays > 0 ? vDays + " days" : Math.round(versionAgeHours) + "h"} ago)`,
                durationMs: Date.now() - start,
            });
        }
    }
    return { flags, checks };
}
