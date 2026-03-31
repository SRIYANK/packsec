import semver from "semver";
import { Flag, CheckEntry, CheckResult } from "../types";

interface RegistryVersionMeta {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  scripts?: Record<string, string>;
}

interface RegistryMeta {
  versions: Record<string, RegistryVersionMeta>;
  "dist-tags": Record<string, string>;
  time: Record<string, string>;
}

const SOURCE = "https://registry.npmjs.org";

export async function diffDeps(
  packageName: string,
  newVersion: string,
  maxAgeHours: number
): Promise<CheckResult> {
  const flags: Flag[] = [];
  const checks: CheckEntry[] = [];
  const start = Date.now();
  const url = `${SOURCE}/${packageName}`;

  let meta: RegistryMeta;
  try {
    const res = await fetch(url, {
      signal: AbortSignal.timeout(6000),
    });
    if (!res.ok) {
      checks.push({
        name: "Dependency Diff",
        source: url,
        passed: true,
        detail: `Registry returned ${res.status} — skipped (fail-open)`,
        durationMs: Date.now() - start,
      });
      return { flags, checks };
    }
    meta = (await res.json()) as RegistryMeta;
  } catch {
    checks.push({
      name: "Dependency Diff",
      source: url,
      passed: true,
      detail: "Skipped — network unavailable (fail-open)",
      durationMs: Date.now() - start,
    });
    return { flags, checks };
  }

  const allVersions = Object.keys(meta.versions ?? {})
    .filter((v) => semver.valid(v))
    .sort(semver.compare);

  const newIdx = allVersions.indexOf(newVersion);
  if (newIdx < 1) {
    checks.push({
      name: "Dependency Diff",
      source: url,
      passed: true,
      detail: newIdx === 0
        ? `${packageName}@${newVersion} is the first version — no previous version to diff against`
        : `Version ${newVersion} not found in version list — skipped`,
      durationMs: Date.now() - start,
    });
    return { flags, checks };
  }

  const prevVersion = [...allVersions.slice(0, newIdx)]
    .reverse()
    .find((v) => semver.major(v) === semver.major(newVersion));

  if (!prevVersion) {
    checks.push({
      name: "Dependency Diff",
      source: url,
      passed: true,
      detail: `No previous version on same major branch for ${packageName}@${newVersion}`,
      durationMs: Date.now() - start,
    });
    return { flags, checks };
  }

  const prevDeps = meta.versions[prevVersion]?.dependencies ?? {};
  const newDeps = meta.versions[newVersion]?.dependencies ?? {};

  const prevKeys = new Set(Object.keys(prevDeps));
  const newKeys = Object.keys(newDeps);
  const addedDeps = newKeys.filter((k) => !prevKeys.has(k));
  const removedDeps = [...prevKeys].filter((k) => !newDeps[k]);

  if (addedDeps.length === 0) {
    checks.push({
      name: "Dependency Diff",
      source: url,
      passed: true,
      detail: `Compared ${packageName}@${prevVersion} → @${newVersion}: no new dependencies introduced. ${newKeys.length} deps total${removedDeps.length > 0 ? `, ${removedDeps.length} removed` : ""}.`,
      durationMs: Date.now() - start,
    });
  } else {
    for (const dep of addedDeps) {
      const range = newDeps[dep];
      const depAge = await getPackageFirstSeen(dep);

      const severity =
        depAge !== null && depAge < 24
          ? "critical"
          : depAge !== null && depAge < 168
            ? "high"
            : "medium";

      flags.push({
        type: "new_dep",
        severity,
        message: `"${dep}@${range}" was introduced in ${packageName}@${newVersion} (not in @${prevVersion})`,
        detail:
          depAge !== null
            ? depAge < 1
              ? `"${dep}" was published < 1 hour ago — EXTREME RED FLAG`
              : `"${dep}" first appeared on npm ${Math.round(depAge)}h ago`
            : `"${dep}" could not be verified in registry`,
      });
    }

    checks.push({
      name: "Dependency Diff",
      source: url,
      passed: false,
      detail: `Compared ${packageName}@${prevVersion} → @${newVersion}: ${addedDeps.length} new dep(s) introduced: ${addedDeps.join(", ")}`,
      durationMs: Date.now() - start,
    });
  }

  return { flags, checks };
}

async function getPackageFirstSeen(pkgName: string): Promise<number | null> {
  try {
    const res = await fetch(`${SOURCE}/${pkgName}`, {
      signal: AbortSignal.timeout(4000),
    });
    if (res.status === 404) return 0;
    const meta = (await res.json()) as { time?: { created?: string } };
    const created = meta.time?.created;
    if (!created) return null;
    return (Date.now() - new Date(created).getTime()) / 3_600_000;
  } catch {
    return null;
  }
}
