package main

import (
	"fmt"
	"regexp"
	"strings"
)

type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var sevNames = []string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

func (s Severity) String() string { return sevNames[s] }

func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

func parseSeverity(s string) (Severity, error) {
	for i, n := range sevNames {
		if strings.EqualFold(n, s) {
			return Severity(i), nil
		}
	}
	return 0, fmt.Errorf("unknown severity %q", s)
}

type Rule struct {
	ID       string
	Category string
	Sev      Severity
	Desc     string
	Re       *regexp.Regexp
}

func rule(id, cat string, sev Severity, desc, pattern string) Rule {
	return Rule{ID: id, Category: cat, Sev: sev, Desc: desc, Re: regexp.MustCompile(pattern)}
}

var rules = []Rule{
	// outbound network
	rule("net-curl", "network", Medium, "curl/wget call", `\b(curl|wget)\s`),
	rule("net-python", "network", Medium, "Python HTTP client", `\b(requests|httpx)\.(get|post|put|patch|delete|request|Session|Client|AsyncClient)\b|aiohttp\.ClientSession|urllib\.request|urllib3\.|http\.client`),
	rule("net-js", "network", Medium, "JS HTTP client", `\bfetch\s*\(|\baxios\b|XMLHttpRequest|\bhttps?\.(request|get)\(|navigator\.sendBeacon`),
	rule("net-go", "network", Medium, "Go HTTP client", `\bhttp\.(Get|Post|PostForm|NewRequest|DefaultClient)\b`),
	rule("net-ps", "network", Medium, "PowerShell web request", `(?i)Invoke-(WebRequest|RestMethod)|Net\.WebClient`),
	rule("net-socket", "network", High, "raw socket / netcat", `\b(nc|ncat|netcat|socat)\s+-|\bsocket\.socket\(|/dev/(tcp|udp)/`),
	rule("net-raw-ip", "network", High, "URL with raw IP address", `https?://\d{1,3}(\.\d{1,3}){3}`),
	rule("net-dns-exfil", "exfil", High, "DNS lookup with dynamic data", `\b(dig|nslookup|host)\s+[^\n]*\$`),

	// exfiltration
	rule("exfil-endpoint", "exfil", High, "known exfil / paste / webhook endpoint", `(?i)(webhook\.site|requestbin|pipedream\.net|ngrok\.io|ngrok-free\.app|interact\.sh|oast\.|burpcollaborator|discord(app)?\.com/api/webhooks|hooks\.slack\.com/services|api\.telegram\.org/bot|pastebin\.com|transfer\.sh|0x0\.st|termbin\.com)`),
	rule("exfil-upload", "exfil", High, "uploads local file over HTTP", `(curl|wget)[^\n]*(-d\s*@|--data(-binary|-raw)?\s*@|-F\s*\S+=@|-T\s|--upload-file|--post-file)`),

	// credential access
	rule("cred-ssh", "credentials", High, "SSH key access", `\.ssh/(id_|authorized_keys|config)|\bid_(rsa|ed25519|ecdsa|dsa)\b`),
	rule("cred-cloud", "credentials", High, "cloud credential files", `\.aws/(credentials|config)|\.config/gcloud|\.azure/|\.kube/config|\.docker/config\.json`),
	rule("cred-files", "credentials", High, "token / credential files", `\.netrc|\.npmrc|\.pypirc|\.git-credentials|\.config/gh/hosts|\.claude/\.credentials|\.claude\.json|\.gnupg/`),
	rule("cred-dotenv", "credentials", Medium, "reads .env file", `(^|[\s"'/(])\.env(\.[\w]+)?\b`),
	rule("cred-store", "credentials", Critical, "keychain / browser credential store", `security\s+(find|dump)-(generic|internet)-password|dump-keychain|secret-tool\s+lookup|Login Data|Cookies\.binarycookies|logins\.json|key4\.db|Local State`),
	rule("cred-env-dump", "credentials", High, "dumps whole environment", `\bprintenv\b|\benv\s*[|>]|os\.environ\.(copy|items)\(|dict\(os\.environ\)|(JSON\.stringify|Object\.(keys|entries))\(process\.env\)|os\.Environ\(\)`),
	rule("cred-secret-env", "credentials", Medium, "reads secret env var", `(?i)\$\{?\w*(API_KEY|TOKEN|SECRET|PASSWORD|PASSWD)\b|(environ|getenv|process\.env)[\[.(\s'"]*\w*(API_KEY|TOKEN|SECRET|PASSWORD)`),

	// hardcoded secrets
	rule("leak-aws", "secret", Critical, "AWS access key", `\b(AKIA|ASIA)[0-9A-Z]{16}\b`),
	rule("leak-github", "secret", Critical, "GitHub token", `\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|github_pat_[A-Za-z0-9_]{60,}`),
	rule("leak-anthropic", "secret", Critical, "Anthropic API key", `sk-ant-[A-Za-z0-9_\-]{20,}`),
	rule("leak-openai", "secret", Critical, "OpenAI API key", `\bsk-proj-[A-Za-z0-9_\-]{20,}|\bsk-[A-Za-z0-9]{48}\b`),
	rule("leak-slack", "secret", Critical, "Slack token", `\bxox[abprs]-[A-Za-z0-9-]{10,}`),
	rule("leak-google", "secret", Critical, "Google API key", `\bAIza[0-9A-Za-z_\-]{35}\b`),
	rule("leak-stripe", "secret", Critical, "Stripe live key", `\b(sk|rk)_live_[0-9a-zA-Z]{24,}`),
	rule("leak-private-key", "secret", Critical, "private key", `-----BEGIN ([A-Z]+ )?PRIVATE KEY-----`),
	rule("leak-jwt", "secret", Medium, "JWT", `\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
	rule("leak-generic", "secret", Medium, "hardcoded secret", `(?i)(api[_-]?key|secret|token|passw(or)?d)["']?\s*[:=]\s*["'][^"'\s$<{]{12,}["']`),

	// execution / obfuscation
	rule("exec-pipe-shell", "exec", Critical, "remote script piped to shell", `(curl|wget)[^|\n]*\|\s*(sudo\s+)?(ba|z)?sh\b|(ba|z)?sh\s+<\(\s*(curl|wget)`),
	rule("exec-b64", "obfuscation", High, "decodes and executes payload", `base64\s+(-d|--decode|-D)[^\n]*\|\s*(ba|z)?sh|eval\s*\(\s*(atob|Buffer\.from)|exec\(\s*(base64\.b64decode|__import__|compile)|marshal\.loads|codecs\.decode\([^)]*rot`),
	rule("exec-dynamic", "exec", Medium, "dynamic code / shell execution", `\beval\s*[($"']|\bexec\s*\(|new Function\(|child_process|shell\s*=\s*True|os\.system\(|os\.popen\(`),
	rule("exec-destructive", "destructive", High, "destructive command", `rm\s+-[rf]{2,}\s+(/|~|\$HOME)|\bmkfs\.|dd\s+if=[^\n]*of=/dev/|chmod\s+-R\s+777\s+/|git\s+push\s+[^\n]*--force`),
	rule("exec-persist", "persistence", High, "persistence mechanism", `\bcrontab\s|LaunchAgents|LaunchDaemons|launchctl\s+(load|bootstrap)|systemctl\s+enable|>>?\s*~?/?\S*\.(bashrc|zshrc|bash_profile|profile)\b`),
	rule("exec-sudo", "exec", Medium, "privilege escalation", `\bsudo\s`),
	rule("tamper-claude", "tampering", High, "modifies Claude Code permissions / hooks", `\.claude/settings(\.local)?\.json|dangerously-skip-permissions|bypassPermissions|"hooks"\s*:`),

	// dependencies installed at runtime
	rule("dep-install", "dependency", Low, "installs packages at runtime", `\b(pip3?|uv\s+pip|poetry)\s+(install|add)\s|\b(npm|pnpm|yarn|bun)\s+(i|install|add)\s|\b(go|cargo|gem)\s+install\s|\bbrew\s+install\s`),
	rule("dep-exec-remote", "dependency", Medium, "runs remote package without install", `\b(npx|bunx|pnpx)\s+(-y|--yes)\b|\buvx\s|\bpipx\s+run\s`),
	rule("dep-custom-index", "dependency", Medium, "custom package index", `--(extra-)?index-url\s|--registry[\s=]`),

	// prompt injection
	rule("inject-override", "prompt-injection", High, "instruction override", `(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions|disregard\s+(the\s+)?(system|previous)\s+prompt|you\s+are\s+now\s+in\s+\w+\s+mode`),
	rule("inject-stealth", "prompt-injection", High, "hides actions from the user", `(?i)(do\s+not|don't|never)\s+(tell|inform|mention|reveal|show|notify)\s+(this\s+)?(to\s+)?(the\s+)?user|without\s+(telling|asking|notifying|informing)\s+the\s+user|silently\s+(run|execute|send|upload|install)`),
	rule("inject-hidden-unicode", "prompt-injection", High, "hidden / bidi unicode characters", `[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{2064}\x{FEFF}\x{E0000}-\x{E007F}]`),
}
