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
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
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
