#!/usr/bin/env node
import { checkAge } from "./checks/age";
import { diffDeps } from "./checks/diff";
import { checkOSV } from "./checks/osv";
import { checkTyposquat } from "./checks/typosquat";
import { checkInstallScript } from "./checks/install-script";
import { Flag, Severity, PackageResult, Config, CheckEntry, CheckResult } from "./types";
import { readFileSync, existsSync, writeFileSync } from "fs";
import { resolve } from "path";
import semver from "semver";

// ─────────────────────────── CLI Args ─────────────────────────────

interface CLIFlags {
  json: boolean;
  report: boolean;
  verbose: boolean;
  community: boolean;
  packages: string[];
}

function parseArgs(argv: string[]): CLIFlags {
  const flags: CLIFlags = {
    json: false,
    report: false,
    verbose: false,
    community: false,
    packages: [],
  };

  for (const arg of argv) {
    if (arg === "--json") flags.json = true;
    else if (arg === "--report") flags.report = true;
    else if (arg === "--verbose" || arg === "-v") flags.verbose = true;
    else if (arg === "--community") flags.community = true;
    else if (!arg.startsWith("-")) flags.packages.push(arg);
  }

  return flags;
}

// ─────────────────────────── Config ───────────────────────────────

function loadConfig(): Config {
  const defaults: Config = {
    blockOn: "high",
    allowList: [],
    denyList: [],
    maxAgeHours: 24,
    offline: false,
  };

  const rcPath = resolve(process.cwd(), ".pacsec.json");
  if (existsSync(rcPath)) {
    return { ...defaults, ...JSON.parse(readFileSync(rcPath, "utf-8")) };
  }

  const pkgPath = resolve(process.cwd(), "package.json");
  if (existsSync(pkgPath)) {
    const pkg = JSON.parse(readFileSync(pkgPath, "utf-8"));
    if (pkg["pacsec"]) return { ...defaults, ...pkg["pacsec"] };
  }

  return defaults;
}

// ─────────────────────── Community Rules ───────────────────────────

interface CommunityRules {
  allowList?: string[];
  denyList?: string[];
  updatedAt?: string;
}

async function fetchCommunityRules(url: string): Promise<CommunityRules> {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
    if (!res.ok) return {};
    return (await res.json()) as CommunityRules;
  } catch {
    return {};
  }
}

// ─────────────────────────── Scoring ──────────────────────────────

const WEIGHTS: Record<string, number> = {
  critical: 40,
  high: 20,
  medium: 10,
  low: 3,
};

const SEVERITY_ORDER: Severity[] = [
  "safe",
  "low",
  "medium",
  "high",
  "critical",
];

function scoreAndSeverity(
  flags: Flag[]
): { score: number; severity: Severity } {
  const score = Math.min(
    100,
    flags.reduce((s, f) => s + (WEIGHTS[f.severity] ?? 0), 0)
  );
  const severity: Severity =
    score >= 70
      ? "critical"
      : score >= 40
        ? "high"
        : score >= 15
          ? "medium"
          : score >= 5
            ? "low"
            : "safe";
  return { score, severity };
}

function isAtLeastAsBadAs(a: Severity, b: Severity): boolean {
  return SEVERITY_ORDER.indexOf(a) >= SEVERITY_ORDER.indexOf(b);
}

// ─────────────────────────── Resolve ──────────────────────────────

async function resolveVersion(
  packageName: string,
  versionRange: string
): Promise<string> {
  const res = await fetch(`https://registry.npmjs.org/${packageName}`, {
    signal: AbortSignal.timeout(5000),
  });
  if (!res.ok) return versionRange;
  const meta = (await res.json()) as {
    "dist-tags"?: Record<string, string>;
    versions?: Record<string, unknown>;
  };
  if (meta["dist-tags"]?.[versionRange]) return meta["dist-tags"][versionRange];
  const versions = Object.keys(meta.versions ?? {}).filter((v) => semver.valid(v));
  return semver.maxSatisfying(versions, versionRange) ?? versionRange;
}

// ─────────────────────────── Analyze ──────────────────────────────

async function analyzePackage(
  rawInput: string,
  config: Config
): Promise<PackageResult> {
  const [packageName, versionSpec] = rawInput.startsWith("@")
    ? (() => {
        const parts = rawInput.slice(1).split("@");
        return [`@${parts[0]}`, parts[1] ?? "latest"] as const;
      })()
    : (() => {
        const atIdx = rawInput.indexOf("@");
        if (atIdx < 1) return [rawInput, "latest"] as const;
        return [rawInput.slice(0, atIdx), rawInput.slice(atIdx + 1)] as const;
      })();

  // Allowlist check
  if (
    config.allowList.some(
      (a) => a === packageName || a === `${packageName}@${versionSpec}`
    )
  ) {
    return {
      name: packageName,
      version: versionSpec,
      resolvedVersion: versionSpec,
      flags: [],
      checks: [{
        name: "Allowlist",
        source: "Local config (.pacsec.json or package.json)",
        passed: true,
        detail: `"${packageName}" is on your allow list — all checks skipped`,
        durationMs: 0,
      }],
      score: 0,
      severity: "safe",
      safe: true,
    };
  }

  // Denylist check
  if (
    config.denyList.some((d) => d === packageName || d.startsWith(packageName))
  ) {
    return {
      name: packageName,
      version: versionSpec,
      resolvedVersion: versionSpec,
      flags: [{
        type: "osv_malicious",
        severity: "critical",
        message: `"${packageName}" is on your deny list`,
      }],
      checks: [{
        name: "Denylist",
        source: "Local config (.pacsec.json or package.json)",
        passed: false,
        detail: `"${packageName}" matched deny list entry — blocked`,
        durationMs: 0,
      }],
      score: 100,
      severity: "critical",
      safe: false,
    };
  }

  const resolvedVersion = config.offline
    ? versionSpec
    : await resolveVersion(packageName, versionSpec).catch(() => versionSpec);

  const results: CheckResult[] = await Promise.all([
    config.offline
      ? { flags: [], checks: [{ name: "Package Age", source: "skipped", passed: true, detail: "Offline mode — skipped", durationMs: 0 }] }
      : checkAge(packageName, resolvedVersion, config.maxAgeHours),
    config.offline
      ? { flags: [], checks: [{ name: "Dependency Diff", source: "skipped", passed: true, detail: "Offline mode — skipped", durationMs: 0 }] }
      : diffDeps(packageName, resolvedVersion, config.maxAgeHours),
    config.offline
      ? { flags: [], checks: [{ name: "Known Vulnerabilities (OSV)", source: "skipped", passed: true, detail: "Offline mode — skipped", durationMs: 0 }] }
      : checkOSV(packageName, resolvedVersion),
    checkTyposquat(packageName),
    config.offline
      ? { flags: [], checks: [{ name: "Install Scripts", source: "skipped", passed: true, detail: "Offline mode — skipped", durationMs: 0 }] }
      : checkInstallScript(packageName, resolvedVersion),
  ]);

  const flags = results.flatMap((r) => r.flags);
  const checks = results.flatMap((r) => r.checks);
  const { score, severity } = scoreAndSeverity(flags);

  return {
    name: packageName,
    version: versionSpec,
    resolvedVersion,
    flags,
    checks,
    score,
    severity,
    safe: !isAtLeastAsBadAs(severity, config.blockOn),
  };
}

// ─────────────────────────── Output ───────────────────────────────

const ICONS: Record<Severity, string> = {
  critical: "🔴",
  high: "🟠",
  medium: "🟡",
  low: "🟢",
  safe: "✅",
};

const REPO_URL = "https://github.com/SRIYANK/packsec";

function renderDetailedResult(result: PackageResult): void {
  const border = "─".repeat(60);
  const icon = ICONS[result.severity];
  const versionStr =
    result.resolvedVersion !== result.version
      ? `${result.version} → ${result.resolvedVersion}`
      : result.version;

  console.log(`\n  ${border}`);
  console.log(`  ${icon}  ${result.name}@${versionStr}`);
  console.log(`  ${border}`);

  if (result.safe) {
    console.log(`  Verdict:  PASSED  (score: ${result.score}/100)`);
  } else {
    console.log(`  Verdict:  BLOCKED  (score: ${result.score}/100, severity: ${result.severity.toUpperCase()})`);
  }

  // Show all checks performed
  console.log(`\n  Checks performed (${result.checks.length}):\n`);

  for (const check of result.checks) {
    const ci = check.passed ? "✅" : "❌";
    console.log(`    ${ci}  ${check.name}`);
    console.log(`       Source:  ${check.source}`);
    console.log(`       Result:  ${check.detail}`);
    if (check.durationMs > 0) {
      console.log(`       Time:    ${check.durationMs}ms`);
    }
    console.log();
  }

  // Show flags if any
  if (result.flags.length > 0) {
    console.log(`  Issues found (${result.flags.length}):\n`);
    for (const flag of result.flags) {
      const fi = ICONS[flag.severity];
      console.log(`    ${fi}  [${flag.severity.toUpperCase()}] ${flag.message}`);
      if (flag.detail) console.log(`       ↳ ${flag.detail}`);
      console.log();
    }
  }
}

function renderCompactResult(result: PackageResult): void {
  const icon = ICONS[result.severity];
  const versionStr =
    result.resolvedVersion !== result.version
      ? `${result.version} → ${result.resolvedVersion}`
      : result.version;

  if (result.severity === "safe" || result.flags.length === 0) {
    console.log(`  ${icon} ${result.name}@${versionStr}`);
    return;
  }

  console.log(
    `\n  ${icon} ${result.name}@${versionStr}  [risk: ${result.score}/100]`
  );
  for (const flag of result.flags) {
    const fi = ICONS[flag.severity];
    console.log(`     ${fi}  ${flag.message}`);
    if (flag.detail) console.log(`        ↳ ${flag.detail}`);
  }
}

function renderBlocked(results: PackageResult[]): void {
  const border = "─".repeat(60);
  console.error(`\n  ${border}`);
  console.error(`  🚨  INSTALLATION BLOCKED  —  packsec`);
  console.error(`  ${border}`);
  for (const r of results) {
    console.error(`\n  Package:  ${r.name}@${r.resolvedVersion}`);
    console.error(`  Risk:     ${r.severity.toUpperCase()} (${r.score}/100)`);
    for (const f of r.flags) {
      console.error(`\n    • ${f.message}`);
      if (f.detail) console.error(`      ↳ ${f.detail}`);
    }
  }
  console.error(`\n  ${border}`);
  console.error(`  To install anyway (not recommended):`);
  console.error(`    PACSEC_SKIP=1 npm install <pkg>`);
  console.error(`\n  Think this is wrong? Report it:`);
  console.error(`    ${REPO_URL}/issues/new`);
  console.error();
}

function renderJsonOutput(results: PackageResult[]): void {
  const output = {
    timestamp: new Date().toISOString(),
    tool: "packsec",
    version: getToolVersion(),
    results: results.map((r) => ({
      package: r.name,
      version: r.version,
      resolvedVersion: r.resolvedVersion,
      verdict: r.safe ? "PASSED" : "BLOCKED",
      score: r.score,
      severity: r.severity,
      checks: r.checks.map((c) => ({
        name: c.name,
        source: c.source,
        passed: c.passed,
        detail: c.detail,
        durationMs: c.durationMs,
      })),
      flags: r.flags.map((f) => ({
        type: f.type,
        severity: f.severity,
        message: f.message,
        detail: f.detail,
      })),
    })),
  };
  console.log(JSON.stringify(output, null, 2));
}

function getToolVersion(): string {
  try {
    const pkgPath = resolve(__dirname, "..", "package.json");
    const pkg = JSON.parse(readFileSync(pkgPath, "utf-8"));
    return pkg.version ?? "unknown";
  } catch {
    return "unknown";
  }
}

function generateReportMarkdown(results: PackageResult[]): string {
  const lines: string[] = [
    `# packsec Scan Report`,
    ``,
    `Generated: ${new Date().toISOString()}`,
    `Tool version: ${getToolVersion()}`,
    ``,
  ];

  for (const r of results) {
    const verdict = r.safe ? "✅ PASSED" : "❌ BLOCKED";
    lines.push(`## ${r.name}@${r.resolvedVersion}`);
    lines.push(``);
    lines.push(`| Field | Value |`);
    lines.push(`|---|---|`);
    lines.push(`| Verdict | ${verdict} |`);
    lines.push(`| Score | ${r.score}/100 |`);
    lines.push(`| Severity | ${r.severity} |`);
    lines.push(``);

    lines.push(`### Checks Performed`);
    lines.push(``);
    lines.push(`| Check | Source | Result | Time |`);
    lines.push(`|---|---|---|---|`);
    for (const c of r.checks) {
      const status = c.passed ? "✅ Passed" : "❌ Failed";
      lines.push(`| ${c.name} | ${c.source} | ${status}: ${c.detail} | ${c.durationMs}ms |`);
    }
    lines.push(``);

    if (r.flags.length > 0) {
      lines.push(`### Issues`);
      lines.push(``);
      for (const f of r.flags) {
        lines.push(`- **[${f.severity.toUpperCase()}]** ${f.message}`);
        if (f.detail) lines.push(`  - ${f.detail}`);
      }
      lines.push(``);
    }
  }

  lines.push(`---`);
  lines.push(`*Report generated by [packsec](${REPO_URL})*`);
  lines.push(`*Found an issue? [Report it](${REPO_URL}/issues/new)*`);

  return lines.join("\n");
}

function generateGitHubIssueUrl(result: PackageResult, type: "false-positive" | "false-negative"): string {
  const title = encodeURIComponent(
    `[${type}] ${result.name}@${result.resolvedVersion}`
  );
  const body = encodeURIComponent(
    [
      `## Package`,
      `- Name: ${result.name}`,
      `- Version: ${result.resolvedVersion}`,
      `- Score: ${result.score}/100`,
      `- Verdict: ${result.safe ? "PASSED" : "BLOCKED"}`,
      ``,
      `## Checks`,
      ...result.checks.map(
        (c) => `- ${c.passed ? "✅" : "❌"} ${c.name}: ${c.detail}`
      ),
      ``,
      `## Why I think this is a ${type}`,
      `<!-- Please explain why you believe this result is incorrect -->`,
      ``,
      `## Additional context`,
      `<!-- Any other information that might help -->`,
    ].join("\n")
  );
  const labels = encodeURIComponent(type);
  return `${REPO_URL}/issues/new?title=${title}&body=${body}&labels=${labels}`;
}

// ──────────────────── Read deps from package.json ─────────────────

function readDepsFromPackageJson(): string[] {
  const pkgPath = resolve(process.cwd(), "package.json");
  if (!existsSync(pkgPath)) return [];

  try {
    const pkg = JSON.parse(readFileSync(pkgPath, "utf-8"));
    const deps = Object.keys(pkg.dependencies ?? {});
    const devDeps = Object.keys(pkg.devDependencies ?? {});
    // Combine and dedupe, attach version ranges
    const all: string[] = [];
    for (const [name, range] of Object.entries(pkg.dependencies ?? {} as Record<string, string>)) {
      if (name === "packsec" || name === "@sriyank/pacsec") continue; // Don't scan ourselves
      all.push(`${name}@${range}`);
    }
    for (const [name, range] of Object.entries(pkg.devDependencies ?? {} as Record<string, string>)) {
      if (name === "packsec" || name === "@sriyank/pacsec") continue;
      if (!all.some((a) => a.startsWith(`${name}@`))) {
        all.push(`${name}@${range}`);
      }
    }
    return all;
  } catch {
    return [];
  }
}

// ─────────────────────────── Main ─────────────────────────────────

async function main(): Promise<void> {
  if (process.env.PACSEC_SKIP === "1") {
    process.exit(0);
  }

  const args = process.argv.slice(2);
  const cli = parseArgs(args);

  let packages = cli.packages;
  let auditMode = false;

  if (packages.length === 0) {
    // Try legacy npm_config_argv first
    const npmArgv = process.env.npm_config_argv
      ? JSON.parse(process.env.npm_config_argv)
      : null;
    packages = (npmArgv?.original ?? []).filter(
      (a: string) => !a.startsWith("-") && a !== "install" && a !== "i"
    );
  }

  if (packages.length === 0) {
    // No args passed — scan all deps from package.json (audit mode)
    packages = readDepsFromPackageJson();
    auditMode = true;
  }

  if (packages.length === 0) {
    console.log(`\n  🛡  packsec — no packages to scan`);
    console.log(`  Usage: npx packsec <package...>`);
    console.log(`  Or add "preinstall": "packsec" to package.json scripts\n`);
    process.exit(0);
  }

  const config = loadConfig();

  // Merge community rules if configured
  if (config.communityRulesUrl || cli.community) {
    const rulesUrl =
      config.communityRulesUrl ??
      `${REPO_URL}/raw/main/community-rules.json`;
    const rules = await fetchCommunityRules(rulesUrl);
    if (rules.allowList) {
      config.allowList = [...new Set([...config.allowList, ...rules.allowList])];
    }
    if (rules.denyList) {
      config.denyList = [...new Set([...config.denyList, ...rules.denyList])];
    }
  }

  if (!cli.json) {
    const mode = auditMode ? "audit mode — scanning all deps from package.json" : `scanning ${packages.length} package(s)`;
    console.log(`\n  🛡  packsec — ${mode}\n`);
  }

  const results = await Promise.all(
    packages.map((pkg) => analyzePackage(pkg, config))
  );

  // JSON output mode
  if (cli.json) {
    renderJsonOutput(results);
    const blocked = results.filter((r) => !r.safe);
    process.exit(blocked.length > 0 ? 1 : 0);
  }

  // Report mode — write markdown file
  if (cli.report) {
    const markdown = generateReportMarkdown(results);
    const reportPath = resolve(process.cwd(), "pacsec-report.md");
    writeFileSync(reportPath, markdown, "utf-8");
    console.log(`  📄  Report saved to: ${reportPath}\n`);
  }

  // Render results (always detailed now)
  for (const result of results) {
    renderDetailedResult(result);
  }

  // Community links
  for (const result of results) {
    if (!result.safe) {
      console.log(
        `  💬  Think "${result.name}" is safe? Report false positive:`
      );
      console.log(
        `      ${generateGitHubIssueUrl(result, "false-positive")}\n`
      );
    }
  }

  const blocked = results.filter((r) => !r.safe);

  if (blocked.length > 0) {
    renderBlocked(blocked);
    process.exit(1);
  }

  const totalMs = results
    .flatMap((r) => r.checks)
    .reduce((sum, c) => sum + c.durationMs, 0);
  console.log(
    `  ✅  All clear. ${results.length} package(s) passed all checks. (${totalMs}ms total)\n`
  );
}

main().catch((err) => {
  console.warn(`  ⚠️  packsec error: ${(err as Error).message}`);
  console.warn(
    `     Proceeding with installation (fail-open for tool errors)\n`
  );
  process.exit(0);
});
