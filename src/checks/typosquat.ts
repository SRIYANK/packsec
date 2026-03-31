import { readFileSync } from "fs";
import { join, resolve } from "path";
import { Flag, CheckEntry, CheckResult } from "../types";

const pkgRoot = resolve(__dirname, "..", "..");
const TOP_1000: string[] = JSON.parse(
  readFileSync(join(pkgRoot, "src", "data", "top-1000.json"), "utf-8")
);

function levenshtein(a: string, b: string): number {
  const m = a.length,
    n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );
  for (let i = 1; i <= m; i++)
    for (let j = 1; j <= n; j++)
      dp[i][j] =
        a[i - 1] === b[j - 1]
          ? dp[i - 1][j - 1]
          : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
  return dp[m][n];
}

export function checkTyposquat(packageName: string): CheckResult {
  const flags: Flag[] = [];
  const checks: CheckEntry[] = [];
  const start = Date.now();

  // Well-known scopes that are never typosquats
  const trustedScopes = /^@(types|babel|angular|vue|react-native|emotion|mui|chakra-ui|testing-library|storybook|aws-sdk|google-cloud|azure|commitlint|typescript-eslint|mdx-js|tanstack|reduxjs|sveltejs|changesets|grpc|jest|hapi|popperjs|sriyank)\//;
  if (trustedScopes.test(packageName)) {
    checks.push({
      name: "Typosquat Detection",
      source: "Bundled top-1000 npm packages list (offline)",
      passed: true,
      detail: `"${packageName}" is under a trusted scope — skipped`,
      durationMs: Date.now() - start,
    });
    return { flags, checks };
  }

  const normalize = (n: string) =>
    n.replace(/^@[\w-]+\//, "").replace(/[-_.]/g, "").toLowerCase();

  const normalized = normalize(packageName);
  let closestMatch: string | null = null;
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
  } else {
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
