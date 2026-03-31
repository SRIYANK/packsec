"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.checkInstallScript = checkInstallScript;
const DANGER_PATTERNS = [
    {
        regex: /exec(?:Sync|File|FileSync)?\s*\(/,
        message: "Shell execution in install script (execSync/exec/execFile)",
        severity: "critical",
    },
    {
        regex: /child_process/,
        message: "child_process imported in install script",
        severity: "high",
    },
    {
        regex: /eval\s*\(/,
        message: "eval() call in install script",
        severity: "critical",
    },
    {
        regex: /new\s+Function\s*\(/,
        message: "new Function() in install script — dynamic code execution",
        severity: "critical",
    },
    {
        regex: /\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){10,}/,
        message: "Heavy hex-encoding in install script — obfuscation pattern",
        severity: "critical",
    },
    {
        regex: /Buffer\.from\([^)]+\)\.toString/,
        message: "Buffer.from().toString() decode — runtime deobfuscation",
        severity: "high",
    },
    {
        regex: /os\.tmpdir\(\)|process\.env\.TEMP|PROGRAMDATA/,
        message: "Writing to system temp/ProgramData in install script",
        severity: "high",
    },
    {
        regex: /fetch\s*\(|https?\.get\s*\(|http\.request\s*\(/,
        message: "Outbound network call in install script",
        severity: "medium",
    },
];
const SOURCE = "https://registry.npmjs.org";
async function checkInstallScript(packageName, version) {
    const flags = [];
    const checks = [];
    const start = Date.now();
    const url = `${SOURCE}/${packageName}/${version}`;
    let versionMeta;
    try {
        const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
        if (!res.ok) {
            checks.push({
                name: "Install Scripts",
                source: url,
                passed: true,
                detail: `Registry returned ${res.status} — skipped (fail-open)`,
                durationMs: Date.now() - start,
            });
            return { flags, checks };
        }
        versionMeta = (await res.json());
    }
    catch {
        checks.push({
            name: "Install Scripts",
            source: url,
            passed: true,
            detail: "Skipped — network unavailable (fail-open)",
            durationMs: Date.now() - start,
        });
        return { flags, checks };
    }
    const scripts = versionMeta.scripts ?? {};
    const installScripts = ["preinstall", "install", "postinstall"]
        .filter((s) => scripts[s])
        .map((s) => ({ name: s, command: scripts[s] }));
    if (installScripts.length === 0) {
        checks.push({
            name: "Install Scripts",
            source: url,
            passed: true,
            detail: `No preinstall/install/postinstall scripts found in ${packageName}@${version}`,
            durationMs: Date.now() - start,
        });
        return { flags, checks };
    }
    for (const { name, command } of installScripts) {
        if (/\bsh\b|\bbash\b|\bcurl\b|\bwget\b|\bpowershell\b/.test(command)) {
            flags.push({
                type: "install_script",
                severity: "high",
                message: `${name} runs shell command: ${command.slice(0, 80)}`,
                detail: "Direct shell invocation during npm install",
            });
        }
        const nodeScriptMatch = command.match(/node\s+([\w./]+\.(?:js|cjs|mjs))/);
        if (nodeScriptMatch && versionMeta.dist?.tarball) {
            const scriptSource = await fetchFileFromTarball(versionMeta.dist.tarball, nodeScriptMatch[1]);
            if (scriptSource) {
                for (const { regex, message, severity } of DANGER_PATTERNS) {
                    if (regex.test(scriptSource)) {
                        flags.push({
                            type: "install_script",
                            severity,
                            message: `${name} (${nodeScriptMatch[1]}): ${message}`,
                            detail: `Detected in ${packageName}@${version}/${nodeScriptMatch[1]}`,
                        });
                    }
                }
            }
        }
    }
    const scriptNames = installScripts.map((s) => s.name).join(", ");
    if (flags.length > 0) {
        checks.push({
            name: "Install Scripts",
            source: url,
            passed: false,
            detail: `Found ${installScripts.length} install script(s) (${scriptNames}) with ${flags.filter((f) => f.type === "install_script").length} dangerous pattern(s)`,
            durationMs: Date.now() - start,
        });
    }
    else {
        checks.push({
            name: "Install Scripts",
            source: url,
            passed: true,
            detail: `Found ${installScripts.length} install script(s) (${scriptNames}) — no dangerous patterns detected`,
            durationMs: Date.now() - start,
        });
    }
    return { flags, checks };
}
async function fetchFileFromTarball(tarballUrl, filename) {
    try {
        const pkgParts = tarballUrl.match(/\/(@[^/]+\/[^/]+|[^/]+)\/-\/.+-(\d+\.\d+\.\d+[^/]*)\.tgz/);
        if (!pkgParts)
            return null;
        const [, pkgName, pkgVersion] = pkgParts;
        const fileUrl = `https://unpkg.com/${pkgName}@${pkgVersion}/${filename}`;
        const res = await fetch(fileUrl, { signal: AbortSignal.timeout(4000) });
        if (!res.ok)
            return null;
        const reader = res.body?.getReader();
        if (!reader)
            return null;
        const chunks = [];
        let totalBytes = 0;
        while (true) {
            const { done, value } = await reader.read();
            if (done || !value)
                break;
            chunks.push(value);
            totalBytes += value.length;
            if (totalBytes > 50_000)
                break;
        }
        return Buffer.concat(chunks).toString("utf-8");
    }
    catch {
        return null;
    }
}
