package kb

import (
	"strings"
	"testing"
)

func TestParseKEV(t *testing.T) {
	body := []byte(`{"catalogVersion":"2026.01.01","vulnerabilities":[{"cveID":"CVE-2021-44228","vendorProject":"Apache","product":"Log4j","vulnerabilityName":"Apache Log4j RCE","dateAdded":"2021-12-10","shortDescription":"RCE","requiredAction":"Apply updates","notes":"https://example.com/kev"}]}`)
	drafts, ver, err := ParseKEV(body, "cisa_kev")
	if err != nil || ver != "2026.01.01" || len(drafts) != 1 {
		t.Fatalf("err=%v ver=%s n=%d", err, ver, len(drafts))
	}
	if drafts[0].ExternalID != "CVE-2021-44228" || !drafts[0].ActivelyExploited {
		t.Fatalf("%+v", drafts[0])
	}
}

func TestParseNucleiYAML(t *testing.T) {
	body := []byte("id: CVE-2021-44228\ninfo:\n  name: Log4j\n  severity: critical\n  description: lookup rce\n  tags: cve,log4j,rce\n  classification:\n    cve-id: CVE-2021-44228\n    cvss-score: 10\n")
	d, ok := ParseNucleiYAML(body, "nuclei_templates")
	if !ok || d.ExternalID != "CVE-2021-44228" || d.Severity != "critical" {
		t.Fatalf("ok=%v %+v", ok, d)
	}
	if len(d.Products) != 1 || d.Products[0] != "log4j" {
		t.Fatalf("products %#v", d.Products)
	}
}

func TestParseNVDAndGHSA(t *testing.T) {
	nvd := []byte(`{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2024-1000","published":"2024-01-02T00:00:00.000","descriptions":[{"lang":"en","value":"gateway bug"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":9.1,"baseSeverity":"CRITICAL"}}]},"references":[{"url":"https://example.com/nvd"}]}}]}`)
	drafts, total, err := ParseNVD(nvd, "nvd_cve", "high")
	if err != nil || total != 1 || len(drafts) != 1 || drafts[0].CVSS != 9.1 {
		t.Fatalf("err=%v total=%d n=%d", err, total, len(drafts))
	}
	low := []byte(`{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2024-1001","descriptions":[{"lang":"en","value":"low"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":3.1,"baseSeverity":"LOW"}}]}}}]}`)
	skipped, _, err := ParseNVD(low, "nvd_cve", "high")
	if err != nil || len(skipped) != 0 {
		t.Fatalf("low kept: %v %d", err, len(skipped))
	}
	ghsa := []byte(`[{"ghsa_id":"GHSA-aaaa-bbbb-cccc","cve_id":"CVE-2024-1000","summary":"gw","severity":"high","published_at":"2024-02-01T00:00:00Z","vulnerabilities":[{"package":{"ecosystem":"maven","name":"spring-cloud-gateway"}}]}]`)
	rows, err := ParseGHSA(ghsa, "github_ghsa")
	if err != nil || len(rows) != 1 || rows[0].ExternalID != "CVE-2024-1000" || rows[0].Products[0] != "spring-cloud-gateway" {
		t.Fatalf("%v %+v", err, rows)
	}
}

func TestParseFeedAndAVD(t *testing.T) {
	rss := []byte(`<?xml version="1.0"?><rss version="2.0"><channel><item><title>泛微 CVE-2024-2222</title><link>https://paper.seebug.org/1/</link><description>desc</description><pubDate>Mon, 02 Jan 2024 00:00:00 GMT</pubDate></item></channel></rss>`)
	rows, err := ParseFeed(rss, "seebug_rss")
	if err != nil || len(rows) != 1 || rows[0].ExternalID != "CVE-2024-2222" {
		t.Fatalf("%v %+v", err, rows)
	}
	html := `<html><title>某产品远程代码执行 - 阿里云</title><body>编号 AVD-2024-9 CVE-2024-3333</body></html>`
	ids := ParseAVDIDs([]byte(html))
	if len(ids) != 1 || ids[0] != "AVD-2024-9" {
		t.Fatalf("ids %#v", ids)
	}
	d, ok := ParseAVDDetail([]byte(html), "AVD-2024-9", "aliyun_avd")
	if !ok || d.ExternalID != "CVE-2024-3333" || !strings.Contains(strings.Join(d.Aliases, ","), "AVD-2024-9") {
		t.Fatalf("%v %+v", ok, d)
	}
}

func TestRedactSensitive(t *testing.T) {
	in := "see https://admin.example.com/login from 10.1.2.3 password=hunter2 Authorization: Bearer abc"
	out := RedactSensitive(in)
	if strings.Contains(out, "admin.example.com") || strings.Contains(out, "10.1.2.3") || strings.Contains(out, "hunter2") || strings.Contains(out, "Bearer abc") {
		t.Fatal(out)
	}
}
