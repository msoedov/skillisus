package main

import (
	"cmp"
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	pyDepsBlockRe = regexp.MustCompile(`(?s)dependencies\s*=\s*\[(.*?)\]`)
	quotedRe      = regexp.MustCompile(`"([^"]+)"|'([^']+)'`)
	pyNameRe      = regexp.MustCompile(`^[A-Za-z0-9_.\-]+`)
	goRequireRe   = regexp.MustCompile(`^\s*(?:require\s+)?([\w.\-]+\.[\w.\-]+/\S+)\s+(v\S+)`)
)

var npmHooks = []string{"preinstall", "install", "postinstall", "prepare"}

func parseDeps(file string, data []byte) ([]Dep, []Finding) {
	base := filepath.Base(file)
	switch {
	case base == "package.json":
		return npmDeps(file, data)
	case strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"):
		return pyReqs(file, string(data))
	case base == "pyproject.toml", strings.HasSuffix(base, ".py") && strings.Contains(string(data), "# /// script"):
		return pyProject(file, string(data))
	case base == "go.mod":
		return goMod(file, string(data)), nil
	}
	return nil, nil
}

func npmDeps(file string, data []byte) ([]Dep, []Finding) {
	var pkg struct {
		Scripts         map[string]string `json:"scripts"`
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if json.Unmarshal(data, &pkg) != nil {
		return nil, nil
	}
	var deps []Dep
	var out []Finding
	for _, m := range []map[string]string{pkg.Dependencies, pkg.DevDependencies} {
		for name, ver := range m {
			deps = append(deps, Dep{Ecosystem: "npm", Name: name, Version: ver, File: file})
			out = append(out, checkVersion(file, name, ver, ver == "" || ver == "*" || ver == "latest")...)
		}
	}
	for _, h := range npmHooks {
		if cmd, ok := pkg.Scripts[h]; ok {
			out = append(out, Finding{Rule: "dep-install-hook", Category: "dependency", Severity: High, Desc: "npm lifecycle script runs on install", File: file, Match: h + ": " + truncate(cmd, 120)})
		}
	}
	return deps, out
}

func pyReqs(file, text string) ([]Dep, []Finding) {
	var deps []Dep
	var out []Finding
	for line := range strings.Lines(text) {
		line, _, _ = strings.Cut(line, "#")
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-") {
			continue
		}
		d, f := pySpec(file, line)
		deps = append(deps, d)
		out = append(out, f...)
	}
	return deps, out
}

func pyProject(file, text string) ([]Dep, []Finding) {
	var deps []Dep
	var out []Finding
	for _, block := range pyDepsBlockRe.FindAllStringSubmatch(text, -1) {
		for _, q := range quotedRe.FindAllStringSubmatch(block[1], -1) {
			d, f := pySpec(file, q[1]+q[2])
			deps = append(deps, d)
			out = append(out, f...)
		}
	}
	return deps, out
}

func pySpec(file, spec string) (Dep, []Finding) {
	name := pyNameRe.FindString(spec)
	ver := strings.TrimSpace(strings.TrimPrefix(spec, name))
	return Dep{Ecosystem: "pypi", Name: cmp.Or(name, spec), Version: ver, File: file},
		checkVersion(file, cmp.Or(name, spec), spec, !strings.Contains(spec, "=="))
}

func goMod(file, text string) []Dep {
	var deps []Dep
	for line := range strings.Lines(text) {
		if m := goRequireRe.FindStringSubmatch(line); m != nil {
			deps = append(deps, Dep{Ecosystem: "go", Name: m[1], Version: m[2], File: file})
		}
	}
	return deps
}

func checkVersion(file, name, spec string, unpinned bool) []Finding {
	if strings.Contains(spec, "git+") || strings.Contains(spec, "://") || strings.HasPrefix(spec, "github:") || strings.HasPrefix(spec, "file:") {
		return []Finding{{Rule: "dep-remote-source", Category: "dependency", Severity: Medium, Desc: "dependency fetched from URL/git/local path", File: file, Match: name + " " + spec}}
	}
	if unpinned {
		return []Finding{{Rule: "dep-unpinned", Category: "dependency", Severity: Low, Desc: "dependency not pinned to exact version", File: file, Match: name + " " + spec}}
	}
	return nil
}
