package kb

import (
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestIsEnrichOnlySource(t *testing.T) {
	cases := []struct {
		src  db.KBSource
		want bool
	}{
		{db.KBSource{Key: "nvd_cve", Kind: "nvd"}, true},
		{db.KBSource{Key: "github_ghsa", Kind: "ghsa"}, true},
		{db.KBSource{Key: "aliyun_avd", Kind: "avd"}, true},
		{db.KBSource{Key: "cisa_kev", Kind: "cisa_kev"}, false},
		{db.KBSource{Key: "nuclei_templates", Kind: "nuclei"}, false},
		// A custom key on an enrich-only feed still enriches; an explicit config wins.
		{db.KBSource{Key: "my_nvd", Kind: "nvd"}, true},
		{db.KBSource{Key: "my_nvd", Kind: "nvd", Config: []byte(`{"enrich_only":false}`)}, false},
		{db.KBSource{Key: "cisa_kev", Kind: "cisa_kev", Config: []byte(`{"enrich_only":true}`)}, true},
		{db.KBSource{Key: "cisa_kev", Kind: "cisa_kev", Config: []byte(`{"enrich_only":"1"}`)}, true},
	}
	for _, c := range cases {
		if got := IsEnrichOnlySource(c.src); got != c.want {
			t.Fatalf("%s/%s enrich_only=%v want %v", c.src.Key, c.src.Kind, got, c.want)
		}
	}
}

func TestDraftEntitled(t *testing.T) {
	local := map[string]bool{"cve:CVE-2022-22947": true, "CVE-2022-22947": true}
	cases := []struct {
		name string
		d    Draft
		want bool
	}{
		{"known CVE enriches", Draft{ExternalID: "CVE-2022-22947", Kind: "cve"}, true},
		{"unknown CVE is dropped", Draft{ExternalID: "CVE-2099-0001", Kind: "cve"}, false},
		{"unknown CVE with PoC enters", Draft{ExternalID: "CVE-2099-0002", Kind: "cve", PocSnippet: "GET / HTTP/1.1"}, true},
		{"unknown KEV enters", Draft{ExternalID: "CVE-2099-0003", Kind: "cve", ActivelyExploited: true}, true},
		{"whitespace PoC does not count", Draft{ExternalID: "CVE-2099-0004", Kind: "cve", PocSnippet: "   "}, false},
	}
	for _, c := range cases {
		if got := DraftEntitled(c.d, local); got != c.want {
			t.Fatalf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestOrderDueSources(t *testing.T) {
	due := []db.KBSource{
		{Key: "seebug_rss"}, {Key: "nvd_cve"}, {Key: "custom_git_kb"},
		{Key: "aliyun_avd"}, {Key: "nuclei_templates"}, {Key: "cisa_kev"},
	}
	got := orderDueSources(due)
	want := []string{"cisa_kev", "nuclei_templates", "aliyun_avd", "nvd_cve", "seebug_rss", "custom_git_kb"}
	for i, key := range want {
		if got[i].Key != key {
			t.Fatalf("order = %v", keysOf(got))
		}
	}
}

func keysOf(srcs []db.KBSource) []string {
	out := make([]string, len(srcs))
	for i, s := range srcs {
		out[i] = s.Key
	}
	return out
}

func TestDraftIsHollow(t *testing.T) {
	cases := []struct {
		name string
		d    Draft
		want bool
	}{
		{"boilerplate guide only", Draft{DetectionGuide: GuideNVD}, true},
		{"kev guide with suffix", Draft{DetectionGuide: GuideKEV + GuideKEVRansomware}, true},
		{"blank guide", Draft{DetectionGuide: ""}, true},
		{"has summary", Draft{DetectionGuide: GuideNVD, Summary: "CVE 描述"}, false},
		{"has PoC", Draft{DetectionGuide: GuideNVD, PocSnippet: "GET / HTTP/1.1"}, false},
		{"known exploited", Draft{DetectionGuide: GuideNVD, ActivelyExploited: true}, false},
		{"custom guide", Draft{DetectionGuide: "按 bash -c 回连验证"}, false},
	}
	for _, c := range cases {
		if got := c.d.IsHollow(); got != c.want {
			t.Fatalf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}
