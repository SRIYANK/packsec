"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.checkTyposquat = checkTyposquat;
const fs_1 = require("fs");
const path_1 = require("path");
const pkgRoot = (0, path_1.resolve)(__dirname, "..", "..");
const TOP_1000 = JSON.parse((0, fs_1.readFileSync)((0, path_1.join)(pkgRoot, "src", "data", "top-1000.json"), "utf-8"));
function levenshtein(a, b) {
    const m = a.length, n = b.length;
    const dp = Array.from({ length: m + 1 }, (_, i) => Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0)));
    for (let i = 1; i <= m; i++)
        for (let j = 1; j <= n; j++)
            dp[i][j] =
                a[i - 1] === b[j - 1]
                    ? dp[i - 1][j - 1]
                    : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    return dp[m][n];
}
function checkTyposquat(packageName) {
    const flags = [];
    const checks = [];
    const start = Date.now();
    const normalize = (n) => n.replace(/^@[\w-]+\//, "").replace(/[-_.]/g, "").toLowerCase();
    const normalized = normalize(packageName);
    let closestMatch = null;
    let closestDist = Infinity;
    for (const popular of TOP_1000) {
        if (packageName === popular) {
            checks.push({
                name: "Typosquat Detection",
                source: "Bundled top-1000 npm packages list (offline)",
                passed: true,
                detail: `"${packageName}" is a known popular package — exact match in top-1000 list`,
                durationMs: Date.now() - start,
            });
            return { flags, checks };
        }
        const dist = levenshtein(normalized, normalize(popular));
        if (dist < closestDist) {
            closestDist = dist;
            closestMatch = popular;
        }
        if (dist === 1) {
            flags.push({
                type: "typosquat",
                severity: "high",
                message: `Possible typosquat of "${popular}" (1 character difference)`,
                detail: `Did you mean: npm install ${popular}`,
            });
            break;
        }
        if (dist === 2 && popular.length > 10) {
            flags.push({
                type: "typosquat",
                severity: "medium",
                message: `Similar to popular package "${popular}"`,
                detail: `Verify this is intentional: ${packageName} vs ${popular}`,
            });
            break;
        }
    }
    if (flags.length > 0) {
        checks.push({
            name: "Typosquat Detection",
            source: "Bundled top-1000 npm packages list (offline)",
            passed: false,
            detail: `"${packageName}" is ${closestDist} edit distance from "${closestMatch}" — possible typosquat`,
            durationMs: Date.now() - start,
        });
    }
    else {
        checks.push({
            name: "Typosquat Detection",
            source: "Bundled top-1000 npm packages list (offline)",
            passed: true,
            detail: closestMatch
                ? `No close matches found. Nearest popular package: "${closestMatch}" (edit distance: ${closestDist})`
                : `No similar packages found in top-1000 list`,
            durationMs: Date.now() - start,
        });
    }
    return { flags, checks };
}
