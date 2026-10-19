package main

import (
	"bytes"
	"cmp"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

const maxFileSize = 2 << 20

// skipDirs are VCS, dependency, cache and build dirs that are not skill content.
var skipDirs = map[string]bool{
	".git": true, ".hg": true, ".svn": true, "node_modules": true, "vendor": true,
	".venv": true, "venv": true, "__pycache__": true, ".mypy_cache": true, ".pytest_cache": true,
	".ruff_cache": true, ".tox": true, ".idea": true, ".vscode": true, "dist": true, "build": true,
	".next": true, ".cache": true, "target": true,
}

// skipFiles are lockfiles and OS junk full of hashes that only produce noise.
var skipFiles = map[string]bool{
	"package-lock.json": true, "yarn.lock": true, "pnpm-lock.yaml": true, "bun.lockb": true,
	"uv.lock": true, "poetry.lock": true, "Pipfile.lock": true, "go.sum": true, "Cargo.lock": true,
	"Gemfile.lock": true, "composer.lock": true, ".DS_Store": true,
}

type Finding struct {
	Rule     string   `json:"rule"`
	Category string   `json:"category"`
	Severity Severity `json:"severity"`
	Desc     string   `json:"desc"`
	File     string   `json:"file"`
	Line     int      `json:"line,omitzero"`
	Match    string   `json:"match,omitempty"`
}

type Dep struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	File      string `json:"file"`
}

type Report struct {
	Root     string    `json:"root"`
	Files    int       `json:"files"`
	Findings []Finding `json:"findings"`
	Deps     []Dep     `json:"deps"`
	Hosts    []string  `json:"hosts"`
}

var (
	urlRe       = regexp.MustCompile(`https?://([A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9])`)
	allowedRe   = regexp.MustCompile(`(?m)^allowed-tools:\s*(.*)$`)
	bareBashRe  = regexp.MustCompile(`\bBash\b(?:[^(]|$)`)
	frontmatter = regexp.MustCompile(`(?s)\A---\n(.*?)\n---`)
)

func Scan(root string) (*Report, error) {
	rep := &Report{Root: root}
	hosts := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			if path != root && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if skipFiles[d.Name()] {
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			rep.Findings = append(rep.Findings, checkSymlink(root, path, rel)...)
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > maxFileSize {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil || isBinary(data) {
			return nil
		}
		rep.Files++
		rep.Findings = append(rep.Findings, scanText(rel, string(data), hosts)...)
		rep.Findings = append(rep.Findings, checkSkillMeta(rel, string(data))...)
		deps, fnd := parseDeps(rel, data)
		rep.Deps = append(rep.Deps, deps...)
		rep.Findings = append(rep.Findings, fnd...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(rep.Findings, func(a, b Finding) int {
		return cmp.Or(cmp.Compare(b.Severity, a.Severity), cmp.Compare(a.File, b.File), cmp.Compare(a.Line, b.Line))
	})
	rep.Hosts = slices.Sorted(maps.Keys(hosts))
	return rep, nil
}

func scanText(file, text string, hosts map[string]bool) []Finding {
	var out []Finding
	foreign, firstForeign, sample := 0, 0, ""
	seenScripts := map[string]bool{}
	for i, line := range strings.Split(text, "\n") {
		for _, m := range urlRe.FindAllStringSubmatch(line, -1) {
			hosts[strings.ToLower(m[1])] = true
		}
		for _, r := range rules {
			m := r.Re.FindString(line)
			if m == "" {
				continue
			}
			snippet := strings.TrimSpace(line)
			if r.Category == "secret" {
				snippet = strings.ReplaceAll(snippet, m, redact(m))
			}
			out = append(out, Finding{Rule: r.ID, Category: r.Category, Severity: r.Sev, Desc: r.Desc, File: file, Line: i + 1, Match: truncate(snippet, 140)})
		}
		out = append(out, scanEncoded(file, i+1, line)...)
		if w := homoglyphWord(line); w != "" {
			out = append(out, Finding{Rule: "homoglyph", Category: "prompt-injection", Severity: High, Desc: "word mixes Latin with Cyrillic/Greek lookalike letters", File: file, Line: i + 1, Match: w})
		}
		if sc := lineScripts(line); len(sc) > 0 {
			foreign++
			if firstForeign == 0 {
				firstForeign, sample = i+1, line
			}
			for k := range sc {
				seenScripts[k] = true
			}
		}
	}
	if foreign > 0 {
		out = append(out, nonLatinFinding(file, foreign, firstForeign, sample, seenScripts))
	}
	return out
}

func checkSkillMeta(file, text string) []Finding {
	if filepath.Base(file) != "SKILL.md" {
		return nil
	}
	fm := frontmatter.FindStringSubmatch(strings.ReplaceAll(text, "\r\n", "\n"))
	if fm == nil {
		return []Finding{{Rule: "skill-no-frontmatter", Category: "skill", Severity: Low, Desc: "SKILL.md has no frontmatter", File: file}}
	}
	m := allowedRe.FindStringSubmatch(fm[1])
	if m == nil || !bareBashRe.MatchString(m[1]) {
		return nil
	}
	return []Finding{{Rule: "skill-unrestricted-bash", Category: "skill", Severity: Medium, Desc: "allowed-tools grants unrestricted Bash", File: file, Match: truncate(m[0], 140)}}
}

func checkSymlink(root, path, rel string) []Finding {
	target, err := os.Readlink(path)
	if err != nil {
		return nil
	}
	abs := target
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(filepath.Dir(path), target)
	}
	if r, err := filepath.Rel(root, abs); err == nil && !strings.HasPrefix(r, "..") {
		return nil
	}
	return []Finding{{Rule: "symlink-escape", Category: "credentials", Severity: High, Desc: "symlink points outside the skill", File: rel, Match: target}}
}

func isBinary(data []byte) bool {
	return bytes.IndexByte(data[:min(len(data), 8000)], 0) >= 0
}

func redact(s string) string {
	if len(s) <= 12 {
		return strings.Repeat("*", len(s))
	}
	return s[:6] + "..." + s[len(s)-4:]
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
