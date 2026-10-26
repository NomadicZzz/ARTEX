package kb

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Autumn-27/artex/db"
	"gopkg.in/yaml.v3"
)

const (
	nucleiCommitURL = "https://api.github.com/repos/projectdiscovery/nuclei-templates/commits/main"
	nucleiZipURL    = "https://codeload.github.com/projectdiscovery/nuclei-templates/zip/refs/heads/main"
	nucleiRawBase   = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/cves"
)

// ParseNucleiYAML turns one template into a draft. ok is false when the file
// has no usable id.
func ParseNucleiYAML(body []byte, sourceKey string) (Draft, bool) {
	var doc map[string]any
	if err := yaml.Unmarshal(body, &doc); err != nil || doc == nil {
		return Draft{}, false
	}
	info, _ := doc["info"].(map[string]any)
	if info == nil {
		return Draft{}, false
	}
	id, _ := doc["id"].(string)
	name, _ := info["name"].(string)
	severity, _ := info["severity"].(string)
	desc, _ := info["description"].(string)
	remediation, _ := info["remediation"].(string)
	class, _ := info["classification"].(map[string]any)
	var cve, cwe string
	var cvss float64
	if class != nil {
		cve = upperCVE(fmt.Sprint(class["cve-id"]))
		cwe = strings.TrimSpace(fmt.Sprint(class["cwe-id"]))
		if cwe == "<nil>" {
			cwe = ""
		}
		switch n := class["cvss-score"].(type) {
		case float64:
			cvss = n
		case int:
			cvss = float64(n)
		}
	}
	if cve == "" {
		cve = upperCVE(id)
	}
	tags := asStringList(info["tags"])
	refs := []db.KBReference{}
	for _, u := range asStringList(info["reference"]) {
		if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
			refs = append(refs, db.KBReference{URL: u})
		}
	}
	products := nucleiProducts(tags, name)
	kind := "poc"
	if cve != "" {
		kind = "cve"
	}
	title := strings.TrimSpace(name)
	if title == "" {
		title = strings.TrimSpace(id)
	}
	if title == "" && cve != "" {
		title = cve
	}
	if title == "" {
		return Draft{}, false
	}
	guide := strings.TrimSpace(desc)
	if guide != "" {
		guide += "\n\n"
	}
	guide += "下列内容来自公开 Nuclei 模板，只作为检测线索。必须在授权目标上真实触发并保留请求/响应后，才能记为漏洞。"
	return Draft{
		ExternalID:     cve,
		Aliases:        nonEmpty(strings.TrimSpace(id)),
		SourceKey:      sourceKey,
		Kind:           kind,
		Severity:       severity,
		CVSS:           cvss,
		CWE:            cwe,
		Products:       products,
		Tags:           tags,
		Title:          title,
		Summary:        clip(desc, 1500),
		DetectionGuide: guide,
		PocSnippet:     clip(string(body), 12000),
		Remediation:    remediation,
		References:     refs,
		NKey:           nucleiNKey(cve, id, title),
	}, true
}

func nucleiNKey(cve, id, title string) string {
	if cve != "" {
		return ""
	}
	base := strings.TrimSpace(id)
	if base == "" {
		base = title
	}
	return "poc:" + slug(base)
}

func slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	dash := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			dash = false
			continue
		}
		if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "template"
	}
	return out
}

func nonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

func nucleiProducts(tags []string, name string) []string {
	skip := map[string]bool{
		"cve": true, "vuln": true, "rce": true, "xss": true, "sqli": true, "lfi": true,
		"ssrf": true, "http": true, "network": true, "tcp": true, "oast": true, "kev": true,
		"intrusive": true, "auth": true, "unauth": true, "default-login": true, "tech": true,
		"panel": true, "detect": true, "exposure": true, "misconfig": true, "info": true,
	}
	var out []string
	for _, t := range tags {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" || skip[t] || strings.HasPrefix(t, "cve") || strings.HasPrefix(t, "cwe") {
			continue
		}
		out = append(out, t)
	}
	return out
}

func nucleiPathWanted(name string) bool {
	n := strings.ToLower(strings.ReplaceAll(name, "\\", "/"))
	if !strings.HasSuffix(n, ".yaml") && !strings.HasSuffix(n, ".yml") {
		return false
	}
	return strings.Contains(n, "/http/cves/") || strings.Contains(n, "/http/vulnerabilities/") || strings.Contains(n, "/network/")
}

func syncNuclei(ctx context.Context, c *Client, src db.KBSource, emit func(Draft) error) (string, error) {
	sha, _ := nucleiHeadSHA(ctx, c)
	if sha != "" && sha == strings.TrimSpace(src.Cursor) {
		return sha, nil
	}
	f, err := os.CreateTemp("", "artex-nuclei-*.zip")
	if err != nil {
		return src.Cursor, err
	}
	name := f.Name()
	f.Close()
	defer os.Remove(name)
	if err := c.Download(ctx, nucleiZipURL, name, 150<<20); err != nil {
		return src.Cursor, err
	}
	zr, err := zip.OpenReader(name)
	if err != nil {
		return src.Cursor, err
	}
	defer zr.Close()
	for _, zf := range zr.File {
		if ctx.Err() != nil {
			return sha, ctx.Err()
		}
		if zf.FileInfo().IsDir() || !nucleiPathWanted(zf.Name) {
			continue
		}
		if zf.UncompressedSize64 > 1<<20 {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			continue
		}
		buf, rerr := io.ReadAll(io.LimitReader(rc, 1<<20))
		rc.Close()
		if rerr != nil || len(buf) == 0 {
			continue
		}
		d, ok := ParseNucleiYAML(buf, src.Key)
		if !ok {
			continue
		}
		if err := emit(d); err != nil {
			return sha, err
		}
	}
	if sha == "" {
		sha = "fetched"
	}
	return sha, nil
}

func nucleiHeadSHA(ctx context.Context, c *Client) (string, error) {
	body, _, err := c.GetBytes(ctx, nucleiCommitURL, map[string]string{"Accept": "application/vnd.github+json"}, 1<<20)
	if err != nil {
		return "", err
	}
	var doc struct {
		SHA string `json:"sha"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", err
	}
	return doc.SHA, nil
}

func fetchNucleiCVE(ctx context.Context, c *Client, sourceKey, cve string) (Draft, error) {
	year := "0000"
	parts := strings.Split(cve, "-")
	if len(parts) >= 2 {
		year = parts[1]
	}
	rawURL := nucleiRawBase + "/" + year + "/" + cve + ".yaml"
	body, _, err := c.GetBytes(ctx, rawURL, nil, 1<<20)
	if err != nil {
		return Draft{}, err
	}
	d, ok := ParseNucleiYAML(body, sourceKey)
	if !ok {
		return Draft{}, fmt.Errorf("模板无法解析")
	}
	return d, nil
}
