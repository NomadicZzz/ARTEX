package db

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestSaveDistilledFindingKB_EnrichAndNew(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { d.Close() })

	ext := fmt.Sprintf("AVD-DISTILL-%d", time.Now().UnixNano())
	nkey := "avd:" + ext
	findingID, err := d.AddFinding(0, 0, "sqli", "沉淀测试漏洞", "high", "发现摘要", "证据里有 Host", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM findings WHERE id=$1`, findingID)
		_, _ = d.Exec(`DELETE FROM kb_entries WHERE nkey=$1 OR nkey=$2`, nkey, fmt.Sprintf("finding:%d", findingID))
	})

	base, _, err := d.UpsertAndMergeKBEntry(KBEntry{
		ExternalID: ext, Origin: "synced", Kind: "cve", Severity: "high",
		Title: "公开条目", Summary: "NVD English summary stays",
		DetectionGuide: "public guide", Products: []string{"Apache Tomcat"}, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if base.NKey != nkey {
		t.Fatalf("nkey=%s", base.NKey)
	}

	heading := findingGuideHeading(findingID)
	saved, err := d.SaveDistilledFindingKB(DistillSave{
		FindingID: findingID, Mode: "enrich_existing", TargetKBID: base.ID,
		Draft: KBEntry{
			DetectionGuide: "看错误回显", PocSnippet: "GET /x HTTP/1.1",
			Remediation: "升级组件", Products: []string{"nginx"}, Tags: []string{"SQLi"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if saved.Summary != "NVD English summary stays" || saved.Title != "公开条目" || saved.Severity != "high" || saved.Kind != "cve" {
		t.Fatalf("enrich overwrote prose: title=%q summary=%q sev=%s kind=%s", saved.Title, saved.Summary, saved.Severity, saved.Kind)
	}
	if strings.Count(saved.DetectionGuide, heading) != 1 || !strings.Contains(saved.DetectionGuide, "public guide") || !strings.Contains(saved.DetectionGuide, "看错误回显") {
		t.Fatalf("guide=%s", saved.DetectionGuide)
	}
	if !strings.Contains(saved.PocSnippet, "GET /x") || saved.Remediation != "升级组件" || !saved.ContentLocked {
		t.Fatalf("poc=%q remediation=%q locked=%v", saved.PocSnippet, saved.Remediation, saved.ContentLocked)
	}
	if !hasString(saved.Products, "tomcat") || !hasString(saved.Products, "nginx") || !hasString(saved.Tags, "sqli") {
		t.Fatalf("products=%v tags=%v", saved.Products, saved.Tags)
	}
	if !hasString(saved.SourceKeys, "finding_distilled") {
		t.Fatalf("source keys=%v", saved.SourceKeys)
	}

	again, err := d.SaveDistilledFindingKB(DistillSave{
		FindingID: findingID, Mode: "enrich_existing", TargetKBID: base.ID,
		Draft: KBEntry{DetectionGuide: "第二版补充", PocSnippet: "POST /y HTTP/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(again.DetectionGuide, heading) != 1 || strings.Contains(again.DetectionGuide, "看错误回显") || !strings.Contains(again.DetectionGuide, "第二版补充") {
		t.Fatalf("section was appended: %s", again.DetectionGuide)
	}
	pocHeading := findingPocHeading(findingID)
	if strings.Count(again.PocSnippet, pocHeading) != 1 || !strings.Contains(again.PocSnippet, "GET /x") || !strings.Contains(again.PocSnippet, "POST /y") {
		t.Fatalf("poc=%s", again.PocSnippet)
	}
	third, err := d.SaveDistilledFindingKB(DistillSave{
		FindingID: findingID, Mode: "enrich_existing", TargetKBID: base.ID,
		Draft: KBEntry{PocSnippet: "PUT /z HTTP/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(third.PocSnippet, pocHeading) != 1 || strings.Contains(third.PocSnippet, "POST /y") || !strings.Contains(third.PocSnippet, "PUT /z") || !strings.Contains(third.PocSnippet, "GET /x") {
		t.Fatalf("poc section duplicated: %s", third.PocSnippet)
	}
	if again.Remediation != "升级组件" || again.Summary != "NVD English summary stays" {
		t.Fatalf("empty incoming cleared fields: remediation=%q summary=%q", again.Remediation, again.Summary)
	}

	created, err := d.SaveDistilledFindingKB(DistillSave{
		FindingID: findingID, Mode: "new_entry",
		Draft: KBEntry{
			Title: fmt.Sprintf("实战条目 %d", findingID), Summary: "实战沉淀摘要，不要被同步覆盖",
			DetectionGuide: "实战指南", Kind: "methodology", Severity: "high", VulnClass: "sqli",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.NKey != fmt.Sprintf("finding:%d", findingID) || created.Origin != "finding_distilled" || !created.ContentLocked || created.ExternalID != "" {
		t.Fatalf("new entry identity: nkey=%s origin=%s locked=%v ext=%s", created.NKey, created.Origin, created.ContentLocked, created.ExternalID)
	}
	if _, _, err = d.UpsertAndMergeKBEntry(KBEntry{
		NKey: created.NKey, Origin: "synced", Kind: "cve", Severity: "critical",
		Title: "NVD overwrite", Summary: "This English summary must not replace the locked prose.",
		Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	locked, err := d.GetKBEntry(created.ID)
	if err != nil || locked == nil {
		t.Fatal(err)
	}
	if locked.Summary != "实战沉淀摘要，不要被同步覆盖" || locked.DetectionGuide != "实战指南" {
		t.Fatalf("sync overwrote locked prose: summary=%q guide=%q", locked.Summary, locked.DetectionGuide)
	}

	rows, total, err := d.SearchKBEntries(KBQuery{SourceKey: "finding_distilled", Q: fmt.Sprintf("实战条目 %d", findingID), Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	if total < 1 || !kbIDs(rows, created.ID) {
		t.Fatalf("source filter missed %d in %d rows", created.ID, total)
	}

	src, err := d.GetFindingDistillSource(findingID)
	if err != nil || src == nil || !src.Distilled {
		t.Fatalf("distilled flag: %+v err=%v", src, err)
	}
}

func kbIDs(rows []KBEntry, id int64) bool {
	for _, row := range rows {
		if row.ID == id {
			return true
		}
	}
	return false
}
