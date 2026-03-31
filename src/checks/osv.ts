import { Flag, CheckEntry, CheckResult } from "../types";

interface OSVQuery {
  vulns?: Array<{
    id: string;
    summary?: string;
    database_specific?: { severity?: string; type?: string };
    affected?: Array<{
      ranges?: Array<{
        events: Array<{ introduced?: string; fixed?: string }>;
      }>;
    }>;
  }>;
}

const SOURCE = "https://api.osv.dev/v1/query";

export async function checkOSV(
  packageName: string,
  version: string
): Promise<CheckResult> {
  const flags: Flag[] = [];
  const checks: CheckEntry[] = [];
  const start = Date.now();

  let data: OSVQuery;
  try {
    const res = await fetch(SOURCE, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      signal: AbortSignal.timeout(5000),
      body: JSON.stringify({
        version,
        package: { name: packageName, ecosystem: "npm" },
      }),
    });
    if (!res.ok) {
      checks.push({
        name: "Known Vulnerabilities (OSV)",
        source: SOURCE,
        passed: true,
        detail: `OSV.dev returned ${res.status} — skipped (fail-open)`,
        durationMs: Date.now() - start,
      });
      return { flags, checks };
    }
    data = (await res.json()) as OSVQuery;
  } catch {
    checks.push({
      name: "Known Vulnerabilities (OSV)",
      source: SOURCE,
      passed: true,
      detail: "Skipped — network unavailable (fail-open)",
      durationMs: Date.now() - start,
    });
    return { flags, checks };
  }

  const vulns = data.vulns ?? [];

  if (vulns.length === 0) {
    checks.push({
      name: "Known Vulnerabilities (OSV)",
      source: SOURCE,
      passed: true,
      detail: `No known vulnerabilities or malware reports for ${packageName}@${version} in OSV.dev database`,
      durationMs: Date.now() - start,
    });
  } else {
    const ids: string[] = [];
    for (const vuln of vulns) {
      const isMalicious =
        vuln.database_specific?.type === "MALICIOUS" ||
        vuln.id?.startsWith("MAL-");

      ids.push(vuln.id);
      flags.push({
        type: isMalicious ? "osv_malicious" : "osv_vuln",
        severity: isMalicious
          ? "critical"
          : osvSeverityMap(vuln.database_specific?.severity),
        message: isMalicious
          ? `KNOWN MALWARE: ${packageName}@${version} — ${vuln.id}`
          : `CVE: ${vuln.id} — ${vuln.summary ?? "No summary"}`,
        detail: `https://osv.dev/vulnerability/${vuln.id}`,
      });
    }

    checks.push({
      name: "Known Vulnerabilities (OSV)",
      source: SOURCE,
      passed: false,
      detail: `${vulns.length} advisory(ies) found: ${ids.join(", ")}. See https://osv.dev for details.`,
      durationMs: Date.now() - start,
    });
  }

  return { flags, checks };
}

function osvSeverityMap(s?: string): "critical" | "high" | "medium" | "low" {
  return (
    (
      {
        CRITICAL: "critical",
        HIGH: "high",
        MEDIUM: "medium",
        LOW: "low",
      } as const
    )[s?.toUpperCase() ?? ""] ?? "medium"
  );
}
