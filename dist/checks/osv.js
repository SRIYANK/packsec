"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.checkOSV = checkOSV;
const SOURCE = "https://api.osv.dev/v1/query";
async function checkOSV(packageName, version) {
    const flags = [];
    const checks = [];
    const start = Date.now();
    let data;
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
        data = (await res.json());
    }
    catch {
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
    }
    else {
        const ids = [];
        for (const vuln of vulns) {
            const isMalicious = vuln.database_specific?.type === "MALICIOUS" ||
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
function osvSeverityMap(s) {
    return ({
        CRITICAL: "critical",
        HIGH: "high",
        MEDIUM: "medium",
        LOW: "low",
    }[s?.toUpperCase() ?? ""] ?? "medium");
}
