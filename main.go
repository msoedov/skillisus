package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

var ghRe = regexp.MustCompile(`^(?:https?://)?(?:www\.)?(?:github\.com/)?([\w.-]+)/([\w.-]+?)(?:\.git)?(?:/tree/([^/]+)(?:/(.+?))?)?/?$`)

type ghTarget struct {
	Repo, Ref, Sub string
}

func parseGitHub(s string) (ghTarget, error) {
	m := ghRe.FindStringSubmatch(s)
	if m == nil {
		return ghTarget{}, fmt.Errorf("not a local dir or GitHub repo: %q", s)
	}
	sub := filepath.Clean("/" + m[4])[1:]
	return ghTarget{Repo: m[1] + "/" + m[2], Ref: m[3], Sub: sub}, nil
}

// resolve returns a local dir to scan, cloning GitHub targets into a temp dir.
func resolve(target string) (string, func(), error) {
	if fi, err := os.Stat(target); err == nil && fi.IsDir() {
		return target, func() {}, nil
	}
	gh, err := parseGitHub(target)
	if err != nil {
		return "", nil, err
	}
	tmp, err := os.MkdirTemp("", "skillisus-*")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { os.RemoveAll(tmp) }
	args := []string{"clone", "--depth", "1", "--quiet", "--no-recurse-submodules"}
	if gh.Ref != "" {
		args = append(args, "--branch", gh.Ref)
	}
	args = append(args, "https://github.com/"+gh.Repo+".git", tmp)
	cmd := exec.Command("git", args...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_LFS_SKIP_SMUDGE=1")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("git clone %s: %w", gh.Repo, err)
	}
	dir := filepath.Join(tmp, gh.Sub)
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		cleanup()
		return "", nil, fmt.Errorf("path %q not found in %s", gh.Sub, gh.Repo)
	}
	return dir, cleanup, nil
}

func filter(rep *Report, min Severity) {
	kept := rep.Findings[:0]
	for _, f := range rep.Findings {
		if f.Severity >= min {
			kept = append(kept, f)
		}
	}
	rep.Findings = kept
}

func printText(w io.Writer, target string, rep *Report) {
	fmt.Fprintf(w, "skillisus: %s (%d files)\n\n", target, rep.Files)
	counts := map[Severity]int{}
	for _, f := range rep.Findings {
		counts[f.Severity]++
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		fmt.Fprintf(w, "%-8s %-16s %-22s %s\n", f.Severity, f.Category, f.Rule, loc)
		fmt.Fprintf(w, "         %s\n", f.Desc)
		if f.Match != "" {
			fmt.Fprintf(w, "         > %s\n", f.Match)
		}
	}
	if len(rep.Deps) > 0 {
		fmt.Fprintf(w, "\nDependencies (%d):\n", len(rep.Deps))
		for _, d := range rep.Deps {
			fmt.Fprintf(w, "  %-5s %s %s  [%s]\n", d.Ecosystem, d.Name, d.Version, d.File)
		}
	}
	if len(rep.Hosts) > 0 {
		fmt.Fprintf(w, "\nHosts referenced (%d):\n  %s\n", len(rep.Hosts), strings.Join(rep.Hosts, "\n  "))
	}
	fmt.Fprintf(w, "\nSummary: %d critical, %d high, %d medium, %d low, %d info\n",
		counts[Critical], counts[High], counts[Medium], counts[Low], counts[Info])
}

func run(args []string, stdout io.Writer) (int, error) {
	fs := flag.NewFlagSet("skillisus", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "print JSON report")
	minFlag := fs.String("min", "low", "minimum severity to show: info|low|medium|high|critical")
	failFlag := fs.String("fail-on", "high", "exit 2 if any finding at or above this severity")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: skillisus [-json] [-min low] [-fail-on high] <dir | owner/repo | github url>")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 1, err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 1, fmt.Errorf("expected exactly one target")
	}
	min, err := parseSeverity(*minFlag)
	if err != nil {
		return 1, err
	}
	failOn, err := parseSeverity(*failFlag)
	if err != nil {
		return 1, err
	}
	dir, cleanup, err := resolve(fs.Arg(0))
	if err != nil {
		return 1, err
	}
	defer cleanup()
	rep, err := Scan(dir)
	if err != nil {
		return 1, err
	}
	rep.Root = fs.Arg(0)
	filter(rep, min)
	if *jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return 1, err
		}
	} else {
		printText(stdout, fs.Arg(0), rep)
	}
	for _, f := range rep.Findings {
		if f.Severity >= failOn {
			return 2, nil
		}
	}
	return 0, nil
}

func main() {
	code, err := run(os.Args[1:], os.Stdout)
	if err != nil && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, "error:", err)
	}
	os.Exit(code)
}
