# 🛡️ packsec

**Vibe-coded or not, your `npm install` deserves a bodyguard.**

[![npm](https://img.shields.io/npm/v/packsec?color=crimson&label=npm)](https://www.npmjs.com/package/packsec)
[![downloads](https://img.shields.io/npm/dm/packsec?color=blue)](https://www.npmjs.com/package/packsec)
[![license](https://img.shields.io/github/license/SRIYANK/packsec)](LICENSE)

---

## Why this exists

You're in the zone. The AI just generated the perfect code. You hit `npm install` and 47 packages fly in. You don't read them. Nobody reads them. That's the vibe.

But here's the thing — attackers know that. The [axios supply chain attack](https://socket.dev/blog/axios-maintainer-account-compromised) worked because a compromised maintainer account pushed a new version with a brand new dependency that ran `execSync` in a postinstall script. It was live for hours. Thousands of installs. Nobody checked.

If you're vibe coding — letting AI write your code, installing packages on instinct, shipping fast — you're moving at a speed where one bad `npm install` can inject malware into your project before you even look at the terminal output.

**packsec is the 1.5-second sanity check between you and that moment.**

It doesn't slow you down. It doesn't need an account. It doesn't phone home. It just asks npm's own registry and Google's OSV database two simple questions: *"Is this package suspiciously new?"* and *"Is it known to be malicious?"* — and blocks the install if the answer is yes.

~500 lines of TypeScript. One dependency. You can read the entire thing during a coffee break.

---

## What it checks

| Check | What it catches | Source |
|---|---|---|
| Package age | Packages created < 24h ago | `registry.npmjs.org` |
| Dependency diff | New deps sneaked into version updates | `registry.npmjs.org` |
| Known malware/CVEs | Flagged packages in OSV database | `api.osv.dev` |
| Typosquatting | `lodasj` instead of `lodash` | Bundled top-1000 list (offline) |
| Install scripts | `execSync`, `eval`, obfuscation in postinstall | `registry.npmjs.org` + `unpkg.com` |

Every check shows its source URL. No black boxes. No "trust us" scores. You see exactly what was queried and what came back.

---

## Install

```bash
# Just run it (zero install)
npx packsec axios lodash react

# Or install globally
npm install -g packsec

# Or per-project (guards the whole team)
npm install --save-dev packsec
```

### Auto-guard every install in a project

```json
{
  "scripts": {
    "preinstall": "packsec"
  },
  "packsec": {
    "blockOn": "high",
    "maxAgeHours": 24
  }
}
```

---

## What you see

Every scan gives you the full picture — even when everything passes:

```
  🛡  packsec — scanning 1 package(s)

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
       Result:  Compared lodash@4.17.21 → @4.17.23: no new deps.
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

When something is wrong, you see exactly why:

```
  🚨  INSTALLATION BLOCKED  —  packsec

  Package:  xyzfakepkg@latest
  Risk:     HIGH (40/100)

    • "xyzfakepkg" does not exist in the npm registry
      ↳ This package was never published — possible phantom dependency attack

  To install anyway (not recommended):
    PACKSEC_SKIP=1 npm install <pkg>
```

---

## CLI Flags

```bash
npx packsec <packages...> [flags]
```

| Flag | What it does |
|---|---|
| `--json` | Full results as JSON — pipe it into CI |
| `--report` | Save a markdown audit trail to `packsec-report.md` |
| `--community` | Pull community allow/deny lists from GitHub |

---

## Configuration

Add to `package.json` under `"packsec"` key, or create `.packsec.json`:

| Field | Default | Description |
|---|---|---|
| `blockOn` | `"high"` | Block at this severity or above |
| `maxAgeHours` | `24` | Flag packages newer than N hours |
| `allowList` | `[]` | Skip checks for these packages |
| `denyList` | `[]` | Always block these packages |
| `offline` | `false` | Skip network checks, bundled data only |
| `communityRulesUrl` | — | URL to shared community rules JSON |

---

## Community

packsec is built in the open and stays in the open.

**Found a false positive?** When packsec blocks something it shouldn't, it prints a pre-filled GitHub issue link. One click and the scan data is already in the issue body.

**Want to improve it?** The entire source is ~500 lines across 6 files. Read it, audit it, fork it, make it better. PRs welcome. If you build something cooler on top of this, that's a win for everyone.

**Community rules:** Opt into shared allow/deny lists maintained by the community:

```bash
npx packsec axios --community
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to propose rule changes, report issues, or contribute code.

---

## Audit it yourself

A security tool you can't read is a liability. packsec is designed to be auditable in under 30 minutes:

```bash
# Clone and count the lines (~500 across 6 files)
git clone https://github.com/SRIYANK/packsec && cd packsec
find src -name "*.ts" | xargs wc -l

# Verify all network calls go to trusted public infrastructure only
grep -r "fetch(" src/
# You'll see: registry.npmjs.org, api.osv.dev, unpkg.com — nothing else

# Verify zero telemetry
grep -r "telemetry\|analytics\|beacon\|track" src/
# Returns nothing

# Check the full dependency tree
npm ls --all
# semver — that's it
```

---

## Trust model

- **One runtime dependency:** `semver` (npm's own package, 6KB, zero deps)
- **Three network targets:** `registry.npmjs.org`, `api.osv.dev`, `unpkg.com` — all public, all already trusted by every npm user
- **Zero telemetry.** Zero accounts. Zero API keys. Zero phone-home. Ever.
- **Fail-open:** If packsec itself errors, it warns and lets the install proceed. Tool bugs never block your work.
- **Full transparency:** Every check shows its source URL, what was queried, and what came back

---

## Emergency override

When you know what you're doing and need to bypass:

```bash
PACKSEC_SKIP=1 npm install <pkg>
```

---

## License

MIT — do whatever you want with it.

---

*Built because vibe coding shouldn't mean vibe trusting.*
*If this saves even one person from a supply chain attack, it was worth building.*
