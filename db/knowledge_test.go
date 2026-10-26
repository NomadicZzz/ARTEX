package db

import "testing"

func TestMergeKBEntryPromotesCVEAndKeepsLockedProse(t *testing.T) {
	existing := KBEntry{
		NKey: "avd:AVD-2024-1", ExternalID: "AVD-2024-1", Origin: "synced", Kind: "cve",
		Title: "阿里云标题", Summary: "短", Severity: "medium", Products: []string{"泛微"},
		SourceKeys: []string{"aliyun_avd"},
	}
	incoming := KBEntry{
		ExternalID: "cve-2024-1000", SourceKeys: []string{"nvd_cve"}, Severity: "critical",
		CVSS: 9.8, Title: "English title that is longer than the Chinese one", Summary: "A much longer english summary",
		ActivelyExploited: true, Products: []string{"Weaver E-Cology"},
	}
	got := MergeKBEntry(existing, incoming)
	if got.NKey != "cve:CVE-2024-1000" || got.ExternalID != "CVE-2024-1000" {
		t.Fatalf("nkey/external = %s %s", got.NKey, got.ExternalID)
	}
	if !got.ActivelyExploited {
		t.Fatal("kev flag cleared")
	}
	if got.Severity != "critical" || got.CVSS != 9.8 {
		t.Fatalf("severity merge = %s %.1f", got.Severity, got.CVSS)
	}
	if got.Title != "阿里云标题" {
		t.Fatalf("han title lost: %s", got.Title)
	}
	if len(got.Products) != 1 || got.Products[0] != "weaver-ecology" {
		t.Fatalf("products = %#v", got.Products)
	}

	locked := existing
	locked.ContentLocked = true
	locked.Title = "人工标题"
	locked.Severity = "low"
	locked.DetectionGuide = "人工检测"
	folded := MergeKBEntry(locked, incoming)
	if folded.Title != "人工标题" || folded.Severity != "low" || folded.DetectionGuide != "人工检测" {
		t.Fatalf("locked prose overwritten: %+v", folded)
	}
	if !folded.ActivelyExploited || folded.NKey != "cve:CVE-2024-1000" {
		t.Fatalf("locked row dropped identity/kev: %+v", folded)
	}
}

func TestPrepareKBEntryLocksManualOrigin(t *testing.T) {
	got, err := prepareKBEntry(KBEntry{Title: "手工检查清单", Origin: "manual", Kind: "checklist", Severity: "info"})
	if err != nil {
		t.Fatal(err)
	}
	if !got.ContentLocked || got.Kind != "checklist" || got.NKey == "" {
		t.Fatalf("%+v", got)
	}
}
