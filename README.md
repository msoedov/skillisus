# skillisus

Static security scanner for Claude Code skills. Point it at a local skill directory or a GitHub repo and it reports risky patterns before you install the skill.

## Install

Requires Go 1.26+ and `git` (for scanning GitHub targets).

```sh
make i        # go install into $GOBIN
# or
make build    # builds ./bin/skillisus
```

## Usage

```sh
skillisus [-json] [-min low] [-fail-on high] <dir | owner/repo | github url>
```

Examples:

```sh
skillisus ~/.claude/skills/my-skill
skillisus anthropics/skills
skillisus https://github.com/owner/repo/tree/main/skills/pdf
skillisus -json -min medium owner/repo > report.json
```

GitHub targets are shallow-cloned into a temp dir (no submodules, no LFS) and removed after the scan.

| Flag | Default | Meaning |
|------|---------|---------|
| `-json` | off | print JSON report instead of text |
| `-min` | `low` | hide findings below this severity: `info`, `low`, `medium`, `high`, `critical` |
| `-fail-on` | `high` | exit 2 if any finding is at or above this severity |

Set `NO_COLOR=1` to disable colored output.

### Exit codes

- `0` no findings at or above `-fail-on`
- `1` usage or scan error
- `2` findings at or above `-fail-on`

## What it checks

- **network**: curl/wget, HTTP clients (Python, JS, Go, PowerShell), raw sockets, raw IP URLs
- **exfil**: webhook/paste/tunnel endpoints, file uploads over HTTP, DNS exfil
- **credentials**: SSH keys, cloud and token files, keychains and browser stores, env dumps, secret env vars
- **secret**: hardcoded AWS, GitHub, Anthropic, OpenAI, Slack, Google, Stripe keys, private keys, JWTs
- **exec / destructive / persistence / tampering**: dangerous shell execution and system changes
- **obfuscation**: base64/hex payloads, high-entropy tokens, non-Latin scripts and homoglyphs
- **dependency**: npm, Python and Go deps fetched from URLs/git or not pinned
- **skill**: `SKILL.md` without frontmatter, `allowed-tools` granting unrestricted `Bash`
- symlinks pointing outside the skill

The report also lists parsed dependencies and every host referenced in URLs. Matched secrets are redacted in output.

Skipped: VCS, dependency and build dirs (`.git`, `node_modules`, `.venv`, `dist`, ...), lockfiles, binary files, files over 2 MB.

## CI

```sh
skillisus -fail-on high ./skills || exit 1
```

## Development

```sh
make test
make lint
```
