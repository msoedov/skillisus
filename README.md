# skillisus

Skillisus is a static security scanner for Claude Code skills. It examines a skill directory or a GitHub repository. It shows the dangerous patterns that it finds. Use it before you install a skill.

## Install

You must have Go 1.26 or higher. To scan a GitHub repository, you must also have `git`.

To install the binary into `$GOBIN`, do this command:

```sh
make i
```

To build the binary into `./bin/skillisus`, do this command:

```sh
make build
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

For a GitHub target, skillisus makes a shallow clone in a temporary directory. It does not get submodules or LFS files. It removes the temporary directory after the scan.

| Flag | Default | Function |
|------|---------|----------|
| `-json` | off | Shows the report in JSON format. |
| `-min` | `low` | Shows only findings at this severity or higher: `info`, `low`, `medium`, `high`, `critical`. |
| `-fail-on` | `high` | Sets exit code 2 if a finding is at this severity or higher. |

To stop colored output, set `NO_COLOR=1`.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | No finding is at the `-fail-on` severity or higher. |
| `1` | A usage error or a scan error occurred. |
| `2` | One or more findings are at the `-fail-on` severity or higher. |

## Checks

Skillisus finds these items:

| Category | Items |
|----------|-------|
| network | curl and wget commands, HTTP clients (Python, JS, Go, PowerShell), raw sockets, URLs with raw IP addresses |
| exfil | Webhook, paste and tunnel endpoints, file uploads over HTTP, DNS exfiltration |
| credentials | SSH keys, cloud credential files, token files, keychains, browser credential stores, environment dumps, secret environment variables |
| secret | Hardcoded AWS, GitHub, Anthropic, OpenAI, Slack, Google and Stripe keys, private keys, JWTs |
| exec, destructive, persistence, tampering | Dangerous shell commands and changes to the system |
| obfuscation | Base64 and hex payloads, high-entropy tokens, non-Latin scripts, homoglyphs |
| dependency | npm, Python and Go dependencies from a URL, git or a local path, dependencies without an exact version |
| skill | A `SKILL.md` file without frontmatter, an `allowed-tools` field that gives unrestricted `Bash` |

Skillisus also finds symlinks that point outside of the skill directory.

The report shows a list of the dependencies. It also shows a list of all hosts in URLs. Skillisus hides the matched secrets in the report.

Skillisus does not scan these items:

- VCS, dependency and build directories, for example `.git`, `node_modules`, `.venv` and `dist`
- Lockfiles
- Binary files
- Files that are larger than 2 MB

## CI

To stop a CI job when skillisus finds a high-severity problem, do this command:

```sh
skillisus -fail-on high ./skills || exit 1
```

## Development

To run the tests, do this command:

```sh
make test
```

To examine the code with `go vet`, do this command:

```sh
make lint
```
