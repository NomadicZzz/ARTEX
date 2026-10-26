package kb

import (
	"encoding/json"
	"html"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	cvePattern  = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,}\b`)
	avdPattern  = regexp.MustCompile(`\bAVD-\d{4}-\d+\b`)
	ghsaPattern = regexp.MustCompile(`\bGHSA-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}\b`)
	tagStrip    = regexp.MustCompile(`(?is)<script[^>]*>.*?</script>|<style[^>]*>.*?</style>|<[^>]+>`)
)

func configMap(raw json.RawMessage) map[string]any {
	var m map[string]any
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &m)
	}
	if m == nil {
		m = map[string]any{}
	}
	return m
}

func configString(m map[string]any, key, def string) string {
	v, _ := m[key].(string)
	v = strings.TrimSpace(v)
	if v == "" {
		return def
	}
	return v
}

func configInt(m map[string]any, key string, def int) int {
	switch v := m[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err == nil {
			return n
		}
	}
	return def
}

func upperCVE(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if cvePattern.MatchString(s) && !strings.Contains(s, " ") {
		return s
	}
	if m := cvePattern.FindString(s); m != "" {
		return strings.ToUpper(m)
	}
	return ""
}

func parseTimeFlexible(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	layouts := []string{
		time.RFC3339,
		"2006-01-02T15:04:05.000",
		"2006-01-02T15:04:05",
		"2006-01-02",
		time.RFC1123Z,
		time.RFC1123,
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			u := t.UTC()
			return &u
		}
	}
	return nil
}

func stripHTML(s string) string {
	s = tagStrip.ReplaceAllString(s, " ")
	s = html.UnescapeString(s)
	return strings.Join(strings.Fields(s), " ")
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if n <= 0 || utf8.RuneCountInString(s) <= n {
		return s
	}
	rs := []rune(s)
	return string(rs[:n])
}

func asStringList(v any) []string {
	switch t := v.(type) {
	case string:
		if strings.TrimSpace(t) == "" {
			return nil
		}
		parts := strings.FieldsFunc(t, func(r rune) bool {
			return r == ',' || r == '\n' || r == ';'
		})
		var out []string
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				out = append(out, p)
			}
		}
		return out
	case []any:
		var out []string
		for _, item := range t {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	default:
		return nil
	}
}

func severityAtLeast(sev, min string) bool {
	return dbSeverityRank(sev) >= dbSeverityRank(min)
}

func dbSeverityRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info", "unknown", "":
		return 1
	default:
		return 1
	}
}

func nvdStamp(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000")
}
