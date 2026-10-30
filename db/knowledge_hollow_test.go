package db

import (
	"fmt"
	"testing"
	"time"
)

// hollowTestGuide is a plausible boilerplate guide: the purge must treat it as
// hollow only when the caller lists it, so the test proves both branches.
const hollowTestGuide = "公开公告只说明影响面，命中不是漏洞证据。"

func TestPurgeHollowSyncedCVEs(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { d.Close() })

	stamp := time.Now().UnixNano()
	hollowCVE := fmt.Sprintf("CVE-2099-%06d", stamp%1000000)
	pooCVE := fmt.Sprintf("CVE-2098-%06d", stamp%1000000)
	hollow := "cve:" + hollowCVE
	realPoC := "cve:" + pooCVE
	distilled := fmt.Sprintf("method:hollow-test-%d", stamp)
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM kb_entries WHERE nkey = ANY($1::text[]) OR external_id = ANY($2::text[])`,
			pgTextArray([]string{hollow, realPoC, distilled}), pgTextArray([]string{hollowCVE, pooCVE}))
	})

	must := func(in KBEntry) KBEntry {
		t.Helper()
		row, _, err := d.UpsertAndMergeKBEntry(in)
		if err != nil {
			t.Fatalf("insert %s: %v", in.NKey, err)
		}
		return row
	}
	must(KBEntry{
		NKey: hollow, ExternalID: hollowCVE, Origin: "synced", Kind: "cve",
		Severity: "high", Title: "空壳 CVE", Summary: "只有公告",
		DetectionGuide: hollowTestGuide, Products: []string{"nginx"}, Enabled: true,
	})
	must(KBEntry{
		NKey: realPoC, ExternalID: pooCVE, Origin: "synced", Kind: "cve",
		Severity: "high", Title: "含 PoC", Summary: "有可用 PoC",
		DetectionGuide: hollowTestGuide, PocSnippet: "GET /x HTTP/1.1", Products: []string{"nginx"}, Enabled: true,
	})
	must(KBEntry{
		NKey: distilled, Origin: "finding_distilled", Kind: "methodology",
		Severity: "high", Title: "内部沉淀", Summary: "实战经验",
		DetectionGuide: hollowTestGuide, Products: []string{"nginx"}, Enabled: true,
	})

	// Without the boilerplate in the filter, only a blank guide counts: nothing goes.
	if _, err := d.PurgeHollowSyncedCVEs(KBHollowFilter{}); err != nil {
		t.Fatalf("purge blank-only: %v", err)
	}
	if got, err := d.GetKBEntryByExternalID(hollowCVE); err != nil || got == nil {
		t.Fatalf("blank-only purge removed the boilerplate row: err=%v got=%v", err, got)
	}

	if _, err := d.PurgeHollowSyncedCVEs(KBHollowFilter{HollowGuides: []string{hollowTestGuide}}); err != nil {
		t.Fatalf("purge: %v", err)
	}
	if got, _ := d.GetKBEntryByExternalID(hollowCVE); got != nil {
		t.Fatalf("hollow row survived purge")
	}
	if got, _ := d.GetKBEntryByExternalID(pooCVE); got == nil {
		t.Fatalf("PoC row was purged")
	}
	if got, _ := d.GetKBEntryByExternalID(distilled); got != nil {
		t.Fatalf("distilled row has no CVE external id; lookup should miss")
	}
	var kept int
	if err := d.QueryRow(`SELECT count(*) FROM kb_entries WHERE nkey = $1`, distilled).Scan(&kept); err != nil || kept != 1 {
		t.Fatalf("distilled row purged: n=%d err=%v", kept, err)
	}
}

func TestPurgeHollowKeepsCitedEntry(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { d.Close() })

	stamp := time.Now().UnixNano()
	ext := fmt.Sprintf("CVE-2097-%06d", stamp%1000000)
	nkey := "cve:" + ext
	findingID, err := d.AddFinding(0, 0, "info_leak", "引用测试", "high", "摘要", "证据", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM findings WHERE id=$1`, findingID)
		_, _ = d.Exec(`DELETE FROM kb_entries WHERE nkey=$1 OR external_id=$2`, nkey, ext)
	})
	row, _, err := d.UpsertAndMergeKBEntry(KBEntry{
		NKey: nkey, ExternalID: ext, Origin: "synced", Kind: "cve",
		Severity: "high", Title: "被漏洞引用", DetectionGuide: hollowTestGuide, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.AddFindingKBEntry(findingID, row.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.PurgeHollowSyncedCVEs(KBHollowFilter{HollowGuides: []string{hollowTestGuide}}); err != nil {
		t.Fatalf("purge: %v", err)
	}
	if got, _ := d.GetKBEntryByExternalID(ext); got == nil {
		t.Fatalf("cited entry was purged")
	}
}

func TestExistingKBRefs(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { d.Close() })

	stamp := time.Now().UnixNano()
	ext := fmt.Sprintf("AVD-HOLLOW-%d", stamp)
	alias := fmt.Sprintf("CVE-2096-%06d", stamp%1000000)
	missing := fmt.Sprintf("CVE-2095-%06d", stamp%1000000)
	nkey := "avd:" + ext
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM kb_entries WHERE nkey=$1 OR external_id=$2 OR $3 = ANY(aliases)`, nkey, ext, alias)
	})
	if _, _, err := d.UpsertAndMergeKBEntry(KBEntry{
		NKey: nkey, ExternalID: ext, Origin: "synced", Kind: "cve",
		Severity: "high", Title: "AVD 富化目标", Aliases: []string{alias}, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	got, err := d.ExistingKBRefs([]string{nkey, ext, alias, missing})
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{nkey, ext, alias} {
		if !got[ref] {
			t.Fatalf("missing ref %q in %#v", ref, got)
		}
	}
	if got[missing] {
		t.Fatalf("unknown ref reported as existing")
	}
}

func TestMatchAssetsBroadTechFilterAndTier0Ordering(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { d.Close() })

	stamp := time.Now().UnixNano()
	nginxCVE := fmt.Sprintf("CVE-2094-%06d", stamp%1000000)
	fastjsonCVE := fmt.Sprintf("CVE-2093-%06d", stamp%1000000)
	pubNginx := "cve:" + nginxCVE
	internalNginx := fmt.Sprintf("method:broadtech-test-%d", stamp)
	publicFastjson := "cve:" + fastjsonCVE
	internalFastjson := fmt.Sprintf("method:fastjson-test-%d", stamp)
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM kb_entries WHERE nkey = ANY($1::text[]) OR external_id = ANY($2::text[])`,
			pgTextArray([]string{pubNginx, internalNginx, publicFastjson, internalFastjson}),
			pgTextArray([]string{nginxCVE, fastjsonCVE}))
	})

	// A plain public nginx CVE: high severity, no PoC, not KEV.
	if _, _, err := d.UpsertAndMergeKBEntry(KBEntry{
		NKey: pubNginx, ExternalID: nginxCVE, Origin: "synced", Kind: "cve",
		Severity: "critical", Title: "公开 nginx CVE", Products: []string{"nginx"}, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	// Internal experience on the same broad token.
	if _, _, err := d.UpsertAndMergeKBEntry(KBEntry{
		NKey: internalNginx, Origin: "finding_distilled", Kind: "methodology",
		Severity: "medium", Title: "nginx 实战排查经验", Products: []string{"nginx"}, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	// Both a public and an internal fastjson row, to check ordering.
	if _, _, err := d.UpsertAndMergeKBEntry(KBEntry{
		NKey: publicFastjson, ExternalID: fastjsonCVE, Origin: "synced", Kind: "cve",
		Severity: "critical", ActivelyExploited: true, Title: "公开 fastjson CVE",
		Products: []string{"fastjson"}, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.UpsertAndMergeKBEntry(KBEntry{
		NKey: internalFastjson, Origin: "finding_distilled", Kind: "poc",
		Severity: "high", Title: "fastjson 实战 PoC", PocSnippet: "POST /api HTTP/1.1",
		Products: []string{"fastjson"}, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	// Broad-only fingerprints pull internal experience and nothing public.
	got, err := d.MatchAssetsAgainstKB([]KBFingerprint{{ID: 1, Techs: []string{"nginx", "java"}}}, 5)
	if err != nil {
		t.Fatal(err)
	}
	var all []KBEntry
	for _, m := range got {
		all = append(all, m.TopEntries...)
	}
	for _, e := range all {
		if e.NKey == pubNginx {
			t.Fatalf("broad nginx fingerprint pulled a public CVE: %s", e.Title)
		}
	}
	foundInternal := false
	for _, e := range all {
		if e.NKey == internalNginx {
			foundInternal = true
		}
	}
	if !foundInternal {
		t.Fatalf("broad nginx fingerprint missed the internal entry: %v", all)
	}

	// A specific token sees both, internal first.
	got, err = d.MatchAssetsAgainstKB([]KBFingerprint{{ID: 2, Techs: []string{"fastjson"}}}, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0].TopEntries) < 2 {
		t.Fatalf("fastjson matches = %+v", got)
	}
	if got[0].TopEntries[0].NKey != internalFastjson {
		t.Fatalf("tier 0 not first: %s", got[0].TopEntries[0].NKey)
	}
}

func TestSearchKBEntriesTierOrder(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { d.Close() })

	stamp := time.Now().UnixNano()
	token := fmt.Sprintf("tierorder%d", stamp%100000000)
	publicCVE := fmt.Sprintf("CVE-2092-%06d", stamp%1000000)
	publicKey := "cve:" + publicCVE
	internalKey := "method:" + token
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM kb_entries WHERE nkey = ANY($1::text[]) OR external_id = $2`, pgTextArray([]string{publicKey, internalKey}), publicCVE)
	})
	if _, _, err := d.UpsertAndMergeKBEntry(KBEntry{
		NKey: publicKey, ExternalID: publicCVE, Origin: "synced", Kind: "cve",
		Severity: "critical", ActivelyExploited: true, Title: token + " 公开条目", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.UpsertAndMergeKBEntry(KBEntry{
		NKey: internalKey, Origin: "finding_distilled", Kind: "methodology",
		Severity: "low", Title: token + " 内部条目", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	rows, total, err := d.SearchKBEntries(KBQuery{Q: token, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(rows) != 2 {
		t.Fatalf("total=%d rows=%d", total, len(rows))
	}
	if rows[0].NKey != internalKey {
		t.Fatalf("tier 0 not first: got %s", rows[0].NKey)
	}
}
