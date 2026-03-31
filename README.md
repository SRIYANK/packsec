# 🛡️ pacsec

Lightweight npm supply chain security guard. ~500 lines. One dependency. Zero telemetry.

Every check shows exactly what was queried, where, and why — full transparency by default.

## What it does

Before `npm install` runs, pacsec checks each package against:

- **Package age** — flags packages created < 24h ago (npm registry)
- **Dependency diff** — detects newly-introduced deps in version updates
- **Known malware** — queries OSV.dev (Google-backed, free, no key)
- **Typosquatting** — offline Levenshtein check against top 1000 packages
- **Install scripts** — scans postinstall hooks for shell exec, eval, obfuscation

All checks hit npm's own registry and OSV.dev only. No proprietary backend. No API key.

## Install

```bash
# Option 1: npx (zero install)
npx pacsec axios lodash react

# Option 2: global
npm install -g pacsec

# Option 3: per-project
npm install --save-dev pacsec
```

## Per-project setup

```json
{
  "scripts": {
    "preinstall": "pacsec"
  },
  "pacsec": {
    "blockOn": "high",
    "maxAgeHours": 24
  }
}
```

## Output

Every scan shows a detailed breakdown of all checks performed, even for passing packages:

```
  ────────────────────────────────────────────────────────────
  ✅  lodash@latest → 4.17.23
  ────────────────────────────────────────────────────────────
  Verdict:  PASSED  (score: 0/100)

  Checks performed (6):

    ✅  Package Age
       Source:  https://registry.npmjs.org/lodash
       Result:  Created Mon, 23 Apr 2012. 115 version(s) published.
       Time:    48ms

    ✅  Dependency Diff
       Source:  https://registry.npmjs.org/lodash
       Result:  Compared lodash@4.17.21 → @4.17.23: no new deps. 0 deps total.
       Time:    114ms

    ✅  Known Vulnerabilities (OSV)
       Source:  https://api.osv.dev/v1/query
       Result:  No known vulnerabilities for lodash@4.17.23
       Time:    575ms

    ✅  Typosquat Detection
       Source:  Bundled top-1000 npm packages list (offline)
       Result:  "lodash" is a known popular package — exact match
       Time:    1ms

    ✅  Install Scripts
       Source:  https://registry.npmjs.org/lodash/4.17.23
       Result:  No install scripts found
       Time:    636ms
```

When something is blocked, you see exactly why with full source links:

```
  ❌  Package Existence
     Source:  https://registry.npmjs.org/xyzfakepkg
     Result:  "xyzfakepkg" returned 404 — not found in npm registry

  Issues found (1):
    🔴  [CRITICAL] "xyzfakepkg" does not exist in the npm registry
       ↳ This package was never published — possible phantom dependency attack
```

## CLI Flags

```bash
npx pacsec <packages...> [flags]
```

| Flag | Description |
|---|---|
| `--json` | Output full results as JSON (for CI/CD pipelines) |
| `--report` | Save a markdown report to `pacsec-report.md` |
| `--community` | Merge community allow/deny lists from GitHub |
| `-v, --verbose` | (Reserved for future use) |

## JSON Output

```bash
npx pacsec axios --json
```

Returns structured JSON with every check, source, timing, and flag — ready for CI integration.

## Markdown Report

```bash
npx pacsec axios lodash --report
```

Generates `pacsec-report.md` with a full audit trail — useful for compliance and code review.

## Community Input

pacsec supports community-maintained allow/deny lists:

```bash
# Use community rules alongside your local config
npx pacsec axios --community
```

Or configure it permanently:

```json
{
  "pacsec": {
    "communityRulesUrl": "https://raw.githubusercontent.com/SRIYANK/pacsec/main/community-rules.json"
  }
}
```

### Reporting false positives / negatives

When pacsec blocks a package, it prints a pre-filled GitHub issue URL. Click it to report a false positive with all scan data included.

You can also:
- Open an issue with the `false-positive` or `false-negative` label
- Propose community rule changes via PR to `community-rules.json`

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## Configuration

Add to `package.json` under `"pacsec"` key, or create `.pacsec.json`:

| Field | Default | Description |
|---|---|---|
| `blockOn` | `"high"` | Block at this severity or above |
| `maxAgeHours` | `24` | Flag packages newer than N hours |
| `allowList` | `[]` | Skip checks for these packages |
| `denyList` | `[]` | Always block these packages |
| `offline` | `false` | Skip network checks, use bundled data only |
| `communityRulesUrl` | — | URL to fetch shared community rules |

## Emergency override

```bash
PACSEC_SKIP=1 npm install <pkg>
```

## Trust model

- One runtime dependency: `semver` (npm's own, 6KB, zero deps)
- Network calls go to: `registry.npmjs.org`, `api.osv.dev`, `unpkg.com`
- Zero telemetry. Zero accounts. Zero API keys.
- Fail-open: tool errors never block installs
- Every check shows its source URL — verify anything yourself

## License

MIT
