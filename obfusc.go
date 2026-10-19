package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"maps"
	"math"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	encTokenRe = regexp.MustCompile(`[A-Za-z0-9+/=_-]{24,}`)
	hexOnlyRe  = regexp.MustCompile(`^[0-9a-fA-F]+$`)
)

const entropyThreshold = 4.3

var scripts = []struct {
	name  string
	table *unicode.RangeTable
}{
	{"Cyrillic", unicode.Cyrillic}, {"Greek", unicode.Greek}, {"Han", unicode.Han},
	{"Arabic", unicode.Arabic}, {"Hebrew", unicode.Hebrew}, {"Hangul", unicode.Hangul},
	{"Hiragana", unicode.Hiragana}, {"Katakana", unicode.Katakana}, {"Thai", unicode.Thai},
	{"Devanagari", unicode.Devanagari},
}

// scanEncoded decodes base64/hex tokens and flags readable or rule-matching payloads,
// and flags high-entropy tokens that do not decode to text.
func scanEncoded(file string, n int, line string) []Finding {
	if strings.Contains(line, "data:image/") || strings.Contains(line, "data:font/") {
		return nil
	}
	var out []Finding
	for _, tok := range encTokenRe.FindAllString(line, -1) {
		f := Finding{Category: "obfuscation", File: file, Line: n}
		decoded := tryDecode(tok)
		switch {
		case decoded != "":
			f.Rule, f.Severity, f.Desc = "obf-encoded-text", Medium, "encoded string decodes to readable text"
			if len(strings.Fields(decoded)) >= 4 {
				f.Severity, f.Desc = High, "encoded string decodes to natural language (possible hidden instructions)"
			}
			if hits := matchRules(decoded); len(hits) > 0 {
				f.Rule, f.Severity = "obf-encoded-payload", max(High, slices.MaxFunc(hits, func(a, b Rule) int { return int(a.Sev - b.Sev) }).Sev)
				f.Desc = "encoded payload contains: " + strings.Join(ruleNames(hits), ", ")
			}
			f.Match = truncate(fmt.Sprintf("%s => %q", redact(tok), decoded), 160)
		case isGibberish(tok):
			f.Rule, f.Severity, f.Desc = "obf-high-entropy", Medium, "high-entropy string (encoded payload or secret)"
			f.Match = redact(tok)
		default:
			continue
		}
		out = append(out, f)
	}
	return out
}

// isGibberish reports long, high-entropy tokens whose characters switch between
// lower, upper and digit far more often than words or CamelCase identifiers do.
func isGibberish(tok string) bool {
	if len(tok) < 32 || entropy(tok) <= entropyThreshold {
		return false
	}
	class := func(b byte) int {
		switch {
		case b >= 'a' && b <= 'z':
			return 0
		case b >= 'A' && b <= 'Z':
			return 1
		case b >= '0' && b <= '9':
			return 2
		}
		return 3
	}
	switches := 0
	for i := 1; i < len(tok); i++ {
		if class(tok[i]) != class(tok[i-1]) {
			switches++
		}
	}
	return switches*100 > (len(tok)-1)*50
}

func tryDecode(tok string) string {
	var b []byte
	var err error
	if len(tok)%2 == 0 && hexOnlyRe.MatchString(tok) {
		b, err = hex.DecodeString(tok)
	} else {
		raw := strings.TrimRight(tok, "=")
		enc := base64.RawStdEncoding
		if strings.ContainsAny(raw, "-_") {
			enc = base64.RawURLEncoding
		}
		b, err = enc.DecodeString(raw)
	}
	if err != nil || !isText(b) {
		return ""
	}
	return string(b)
}

func isText(b []byte) bool {
	if len(b) < 8 || !utf8.Valid(b) {
		return false
	}
	total, printable, letters := 0, 0, 0
	for _, r := range string(b) {
		total++
		if unicode.IsPrint(r) || r == '\n' || r == '\t' || r == '\r' {
			printable++
		}
		if unicode.IsLetter(r) {
			letters++
		}
	}
	return printable*100 >= total*95 && letters*100 >= total*40
}

func entropy(s string) float64 {
	freq := map[rune]int{}
	for _, r := range s {
		freq[r]++
	}
	var h float64
	n := float64(utf8.RuneCountInString(s))
	for _, c := range freq {
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

func matchRules(text string) []Rule {
	var hits []Rule
	for _, r := range rules {
		if r.Re.MatchString(text) {
			hits = append(hits, r)
		}
	}
	return hits
}

func ruleNames(rs []Rule) []string {
	var names []string
	for _, r := range rs {
		names = append(names, r.ID)
	}
	return names
}

// lineScripts returns the non-Latin scripts used in line, ignoring lines with fewer than 3 such letters.
func lineScripts(line string) map[string]int {
	var found map[string]int
	total := 0
	for _, r := range line {
		if !unicode.IsLetter(r) || unicode.Is(unicode.Latin, r) {
			continue
		}
		name := "other"
		for _, s := range scripts {
			if unicode.Is(s.table, r) {
				name = s.name
				break
			}
		}
		if found == nil {
			found = map[string]int{}
		}
		found[name]++
		total++
	}
	if total < 3 {
		return nil
	}
	return found
}

// homoglyphWord returns the first word mixing Latin with Cyrillic or Greek letters.
func homoglyphWord(line string) string {
	for _, w := range strings.FieldsFunc(line, func(r rune) bool { return !unicode.IsLetter(r) }) {
		latin := strings.IndexFunc(w, func(r rune) bool { return unicode.Is(unicode.Latin, r) }) >= 0
		other := strings.IndexFunc(w, func(r rune) bool { return unicode.In(r, unicode.Cyrillic, unicode.Greek) }) >= 0
		if latin && other {
			return w
		}
	}
	return ""
}

func nonLatinFinding(file string, lines int, firstLine int, sample string, seen map[string]bool) Finding {
	sev := Low
	if filepath.Ext(file) == ".md" {
		sev = Medium
	}
	names := slices.Sorted(maps.Keys(seen))
	return Finding{
		Rule: "non-latin-text", Category: "prompt-injection", Severity: sev, File: file, Line: firstLine,
		Desc:  fmt.Sprintf("%d line(s) in non-Latin script (%s); review for hidden instructions", lines, strings.Join(names, ", ")),
		Match: truncate(strings.TrimSpace(sample), 140),
	}
}
