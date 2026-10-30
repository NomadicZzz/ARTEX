package kb

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

const (
	nvdBase  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	ghsaBase = "https://api.github.com/advisories"
)

var linkNext = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

func syncNVD(ctx context.Context, c *Client, src db.KBSource, emit func(Draft) error) (string, error) {
	cfg := configMap(src.Config)
	minSev := configString(cfg, "min_severity", "high")
	days := configInt(cfg, "since_days", 120)
	if days <= 0 || days > 119 {
		days = 119
	}
	end := time.Now().UTC()
	start := end.AddDate(0, 0, -days)
	if t := parseTimeFlexible(src.Cursor); t != nil && end.Sub(*t) < 119*24*time.Hour && t.Before(end) {
		start = *t
	}
	apiKey := configString(cfg, "api_key", "")
	headers := map[string]string{}
	if apiKey != "" {
		headers["apiKey"] = apiKey
	}
	gap := 6500 * time.Millisecond
	if apiKey != "" {
		gap = 700 * time.Millisecond
	}
	cursor := nvdStamp(end)
	for page := 0; page < 20; page++ {
		if ctx.Err() != nil {
			return src.Cursor, ctx.Err()
		}
		q := url.Values{}
		q.Set("lastModStartDate", nvdStamp(start))
		q.Set("lastModEndDate", nvdStamp(end))
		q.Set("resultsPerPage", "100")
		q.Set("startIndex", fmt.Sprintf("%d", page*100))
		body, _, err := c.GetBytes(ctx, nvdBase+"?"+q.Encode(), headers, 8<<20)
		if err != nil {
			return src.Cursor, err
		}
		drafts, total, err := ParseNVD(body, src.Key, minSev)
		if err != nil {
			return src.Cursor, err
		}
		for _, d := range drafts {
			if err := emit(d); err != nil {
				return cursor, err
			}
		}
		if (page+1)*100 >= total || total == 0 {
			break
		}
		select {
		case <-ctx.Done():
			return cursor, ctx.Err()
		case <-time.After(gap):
		}
	}
	return cursor, nil
}

func fetchNVDByCVE(ctx context.Context, c *Client, src db.KBSource, cve string) ([]Draft, error) {
	cfg := configMap(src.Config)
	headers := map[string]string{}
	if key := configString(cfg, "api_key", ""); key != "" {
		headers["apiKey"] = key
	}
	q := url.Values{}
	q.Set("cveId", cve)
	body, _, err := c.GetBytes(ctx, nvdBase+"?"+q.Encode(), headers, 4<<20)
	if err != nil {
		return nil, err
	}
	drafts, _, err := ParseNVD(body, src.Key, "")
	return drafts, err
}

// ParseNVD decodes one NVD API 2.0 page. minSeverity empty keeps every CVE.
func ParseNVD(body []byte, sourceKey, minSeverity string) ([]Draft, int, error) {
	var doc struct {
		TotalResults    int `json:"totalResults"`
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Published    string `json:"published"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics    map[string][]map[string]any `json:"metrics"`
				Weaknesses []struct {
					Description []struct {
						Lang  string `json:"lang"`
						Value string `json:"value"`
					} `json:"description"`
				} `json:"weaknesses"`
				Configurations []struct {
					Nodes []struct {
						CPEMatch []struct {
							Criteria   string `json:"criteria"`
							Vulnerable bool   `json:"vulnerable"`
						} `json:"cpeMatch"`
					} `json:"nodes"`
				} `json:"configurations"`
				References []struct {
					URL string `json:"url"`
				} `json:"references"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, 0, err
	}
	var out []Draft
	for _, item := range doc.Vulnerabilities {
		cve := item.CVE
		id := upperCVE(cve.ID)
		if id == "" {
			continue
		}
		sev, score := nvdSeverity(cve.Metrics)
		if minSeverity != "" && !severityAtLeast(sev, minSeverity) {
			continue
		}
		summary := ""
		for _, d := range cve.Descriptions {
			if d.Lang == "en" || summary == "" {
				summary = d.Value
			}
			if d.Lang == "en" {
				break
			}
		}
		var cwe string
		for _, w := range cve.Weaknesses {
			for _, d := range w.Description {
				if strings.HasPrefix(d.Value, "CWE-") {
					cwe = d.Value
					break
				}
			}
		}
		var cpes, products []string
		for _, cfg := range cve.Configurations {
			for _, node := range cfg.Nodes {
				for _, m := range node.CPEMatch {
					if !m.Vulnerable || m.Criteria == "" {
						continue
					}
					cpes = append(cpes, m.Criteria)
					products = append(products, m.Criteria)
				}
			}
		}
		var refs []db.KBReference
		for _, r := range cve.References {
			if r.URL != "" {
				refs = append(refs, db.KBReference{URL: r.URL})
			}
		}
		out = append(out, Draft{
			ExternalID:     id,
			SourceKey:      sourceKey,
			Kind:           "cve",
			Severity:       sev,
			CVSS:           score,
			CWE:            cwe,
			Products:       products,
			CPE:            cpes,
			Title:          id,
			Summary:        summary,
			DetectionGuide: GuideNVD,
			References:     refs,
			PublishedAt:    parseTimeFlexible(cve.Published),
		})
	}
	return out, doc.TotalResults, nil
}

func nvdSeverity(metrics map[string][]map[string]any) (string, float64) {
	for _, key := range []string{"cvssMetricV31", "cvssMetricV30", "cvssMetricV2"} {
		list := metrics[key]
		if len(list) == 0 {
			continue
		}
		data, _ := list[0]["cvssData"].(map[string]any)
		if data == nil {
			continue
		}
		sev, _ := data["baseSeverity"].(string)
		score, _ := data["baseScore"].(float64)
		if sev == "" {
			sev = "info"
		}
		return strings.ToLower(sev), score
	}
	return "info", 0
}

func syncGHSA(ctx context.Context, c *Client, src db.KBSource, emit func(Draft) error) (string, error) {
	cfg := configMap(src.Config)
	return walkGHSA(ctx, c, src.Key, configString(cfg, "api_key", ""), "", configString(cfg, "min_severity", "high"), configInt(cfg, "since_days", 120), emit)
}

func fetchGHSAByCVE(ctx context.Context, c *Client, src db.KBSource, cve string) ([]Draft, error) {
	cfg := configMap(src.Config)
	var out []Draft
	_, err := walkGHSA(ctx, c, src.Key, configString(cfg, "api_key", ""), cve, "", 0, func(d Draft) error {
		out = append(out, d)
		return nil
	})
	return out, err
}

func walkGHSA(ctx context.Context, c *Client, sourceKey, token, cve, minSev string, sinceDays int, emit func(Draft) error) (string, error) {
	headers := map[string]string{"Accept": "application/vnd.github+json"}
	if token != "" {
		headers["Authorization"] = "Bearer " + token
	}
	var since time.Time
	if sinceDays > 0 {
		if sinceDays > 119 {
			sinceDays = 119
		}
		since = time.Now().UTC().AddDate(0, 0, -sinceDays)
	}
	next := ghsaBase + "?per_page=100"
	if cve != "" {
		next += "&cve_id=" + url.QueryEscape(cve)
	}
	var newest string
	for page := 0; page < 20 && next != ""; page++ {
		body, hdr, err := c.GetBytes(ctx, next, headers, 8<<20)
		if err != nil {
			return "", err
		}
		drafts, err := ParseGHSA(body, sourceKey)
		if err != nil {
			return "", err
		}
		stop := false
		for _, d := range drafts {
			if !since.IsZero() && d.PublishedAt != nil && d.PublishedAt.Before(since) {
				stop = true
				continue
			}
			if minSev != "" && !severityAtLeast(d.Severity, minSev) {
				continue
			}
			if newest == "" && d.PublishedAt != nil {
				newest = d.PublishedAt.UTC().Format(time.RFC3339)
			}
			if err := emit(d); err != nil {
				return newest, err
			}
		}
		if stop {
			break
		}
		next = ""
		if m := linkNext.FindStringSubmatch(hdr.Get("Link")); len(m) == 2 {
			next = m[1]
		}
	}
	if newest == "" {
		newest = time.Now().UTC().Format(time.RFC3339)
	}
	return newest, nil
}

// ParseGHSA decodes a GitHub advisories JSON array.
func ParseGHSA(body []byte, sourceKey string) ([]Draft, error) {
	var rows []map[string]any
	if err := json.Unmarshal(body, &rows); err != nil {
		var one map[string]any
		if err2 := json.Unmarshal(body, &one); err2 != nil {
			return nil, err
		}
		rows = []map[string]any{one}
	}
	var out []Draft
	for _, row := range rows {
		ghsa, _ := row["ghsa_id"].(string)
		cve := upperCVE(fmt.Sprint(row["cve_id"]))
		summary, _ := row["summary"].(string)
		desc, _ := row["description"].(string)
		sev, _ := row["severity"].(string)
		var score float64
		if cvss, ok := row["cvss"].(map[string]any); ok {
			score, _ = cvss["score"].(float64)
		}
		var cwe string
		if list, ok := row["cwes"].([]any); ok {
			for _, item := range list {
				m, _ := item.(map[string]any)
				if m == nil {
					continue
				}
				if id, _ := m["cwe_id"].(string); strings.HasPrefix(id, "CWE-") {
					cwe = id
					break
				}
			}
		}
		var products []string
		if list, ok := row["vulnerabilities"].([]any); ok {
			for _, item := range list {
				m, _ := item.(map[string]any)
				pkg, _ := m["package"].(map[string]any)
				if pkg == nil {
					continue
				}
				name, _ := pkg["name"].(string)
				if name != "" {
					products = append(products, name)
				}
			}
		}
		var refs []db.KBReference
		for _, u := range asStringList(row["references"]) {
			refs = append(refs, db.KBReference{URL: u})
		}
		if htmlURL, _ := row["html_url"].(string); htmlURL != "" {
			refs = append(refs, db.KBReference{URL: htmlURL, Title: ghsa})
		}
		ext := cve
		aliases := nonEmpty(ghsa)
		if ext == "" {
			ext = ghsa
			aliases = nil
		}
		title := summary
		if title == "" {
			title = ext
		}
		published, _ := row["published_at"].(string)
		out = append(out, Draft{
			ExternalID:     ext,
			Aliases:        aliases,
			SourceKey:      sourceKey,
			Kind:           "cve",
			Severity:       sev,
			CVSS:           score,
			CWE:            cwe,
			Products:       products,
			Title:          title,
			Summary:        clip(desc, 2000),
			DetectionGuide: GuideGHSA,
			References:     refs,
			PublishedAt:    parseTimeFlexible(published),
		})
	}
	return out, nil
}
