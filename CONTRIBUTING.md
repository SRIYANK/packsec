# Contributing to packsec

## Reporting false positives / false negatives

If packsec incorrectly blocks a safe package or misses a malicious one:

1. Run `npx packsec <package> --json` to get the full scan output
2. Open an issue with the `false-positive` or `false-negative` label
3. Include the JSON output and explain why you believe the result is wrong

The CLI generates a pre-filled issue URL when it blocks a package — use that link.

## Updating community rules

The `community-rules.json` file contains shared allow/deny lists that anyone can opt into via `--community` flag or the `communityRulesUrl` config option.

To propose a change:

1. Fork this repo
2. Edit `community-rules.json`
3. Open a PR with evidence (link to npm advisory, OSV entry, or analysis)

Rules for additions:
- **denyList**: must include a link to a public advisory (OSV, Snyk, npm) or a detailed write-up
- **allowList**: must explain why the package triggers a false positive and why it's safe
- All entries are reviewed by maintainers before merge

## Updating the top-1000 list

The `src/data/top-1000.json` file is the bundled list used for typosquat detection. To update it:

1. Pull the latest download counts from npm
2. Replace the file with the updated list
3. Open a PR

## Code contributions

- Keep the total source under 600 lines
- Zero new runtime dependencies (semver is the only one allowed)
- All network calls must go to: registry.npmjs.org, api.osv.dev, or unpkg.com
- No telemetry, analytics, or phone-home of any kind
- Run `npm run build` and test with a few packages before submitting

## Testing

```bash
npm run build
node bin/packsec.js lodash          # should pass
node bin/packsec.js lodasj          # should flag typosquat
node bin/packsec.js xyzfakepkg999   # should block (phantom dep)
node bin/packsec.js lodash --json   # should output JSON
node bin/packsec.js lodash --report # should write markdown report
```
