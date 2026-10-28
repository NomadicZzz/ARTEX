package db

import (
	"fmt"
	"strings"
)

// DistillSave is one confirmed distillation write.
type DistillSave struct {
	FindingID  int64
	Mode       string // enrich_existing | new_entry
	TargetKBID int64
	Draft      KBEntry
}

// SaveDistilledFindingKB writes a distilled draft. enrich_existing appends a
// per-finding section onto the target row and does not replace its summary.
// new_entry upserts the stable finding:<id> row and replaces that row's prose
// so a second confirm updates the same entry instead of appending forever.
func (d *DB) SaveDistilledFindingKB(in DistillSave) (KBEntry, error) {
	if in.FindingID <= 0 {
		return KBEntry{}, fmt.Errorf("finding id 无效")
	}
	switch in.Mode {
	case "enrich_existing":
		return d.enrichDistilledFinding(in)
	case "new_entry", "":
		return d.insertDistilledFinding(in)
	default:
		return KBEntry{}, fmt.Errorf("未知沉淀模式 %s", in.Mode)
	}
}

func (d *DB) enrichDistilledFinding(in DistillSave) (KBEntry, error) {
	if in.TargetKBID <= 0 {
		return KBEntry{}, fmt.Errorf("未指定要补充的知识条目")
	}
	cur, err := d.GetKBEntry(in.TargetKBID)
	if err != nil {
		return KBEntry{}, err
	}
	if cur == nil {
		return KBEntry{}, fmt.Errorf("知识条目不存在")
	}
	draft := sanitizeKBEntry(in.Draft)
	cur.Products = NormalizeProducts(append(append([]string{}, cur.Products...), draft.Products...))
	cur.Tags = normalizeTags(append(append([]string{}, cur.Tags...), draft.Tags...))
	cur.SourceKeys = unionStrings(cur.SourceKeys, []string{"finding_distilled"})
	cur.DetectionGuide = upsertMarkedSection(cur.DetectionGuide, findingGuideHeading(in.FindingID), draft.DetectionGuide)
	cur.PocSnippet = mergePocSnippet(cur.PocSnippet, draft.PocSnippet, in.FindingID)
	if strings.TrimSpace(cur.Remediation) == "" {
		cur.Remediation = strings.TrimSpace(draft.Remediation)
	}
	cur.Distilled = true
	cur.ContentLocked = true
	if err := d.writeDistilledEntry(*cur); err != nil {
		return KBEntry{}, err
	}
	if err := d.AddFindingKBEntry(in.FindingID, cur.ID); err != nil {
		return KBEntry{}, err
	}
	saved, err := d.GetKBEntry(cur.ID)
	if err != nil || saved == nil {
		return *cur, err
	}
	return *saved, nil
}

func (d *DB) insertDistilledFinding(in DistillSave) (KBEntry, error) {
	draft := sanitizeKBEntry(in.Draft)
	nkey := fmt.Sprintf("finding:%d", in.FindingID)
	entry := KBEntry{
		NKey: nkey, Title: draft.Title, Summary: draft.Summary, DetectionGuide: draft.DetectionGuide,
		PocSnippet: draft.PocSnippet, Remediation: draft.Remediation,
		Kind: draft.Kind, Severity: draft.Severity, VulnClass: draft.VulnClass,
		Products: draft.Products, Tags: draft.Tags,
		Origin: "finding_distilled", SourceKeys: unionStrings(draft.SourceKeys, []string{"finding_distilled"}),
		Distilled: true, Enabled: true,
	}
	if entry.Kind == "" {
		entry.Kind = "methodology"
	}
	row, _, err := d.UpsertAndMergeKBEntry(entry)
	if err != nil {
		return KBEntry{}, err
	}
	// A locked finding row ignores a later merge. The confirmed draft is the
	// source of truth for this nkey, so replace its prose in place.
	if row.NKey == nkey || row.Origin == "finding_distilled" {
		row.Title = entry.Title
		row.Summary = entry.Summary
		row.DetectionGuide = entry.DetectionGuide
		row.PocSnippet = entry.PocSnippet
		row.Remediation = entry.Remediation
		row.Kind = entry.Kind
		row.Severity = entry.Severity
		row.VulnClass = entry.VulnClass
		row.Products = NormalizeProducts(append(append([]string{}, row.Products...), entry.Products...))
		row.Tags = normalizeTags(append(append([]string{}, row.Tags...), entry.Tags...))
		row.SourceKeys = unionStrings(row.SourceKeys, []string{"finding_distilled"})
		row.Origin = "finding_distilled"
		row.Distilled = true
		row.ContentLocked = true
		row.Enabled = true
		if err := d.writeDistilledEntry(row); err != nil {
			return KBEntry{}, err
		}
	}
	if err := d.AddFindingKBEntry(in.FindingID, row.ID); err != nil {
		return KBEntry{}, err
	}
	saved, err := d.GetKBEntry(row.ID)
	if err != nil || saved == nil {
		return row, err
	}
	return *saved, nil
}

func (d *DB) writeDistilledEntry(e KBEntry) error {
	e = sanitizeKBEntry(e)
	e.Products = NormalizeProducts(e.Products)
	e.Tags = normalizeTags(e.Tags)
	e.ContentHash = kbContentHash(e)
	e.ContentLocked = true
	e.Distilled = true
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := updateKBEntry(tx, e); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE kb_entries SET content_locked=true, distilled=true, origin=$2 WHERE id=$1`, e.ID, e.Origin); err != nil {
		return err
	}
	return tx.Commit()
}

func findingGuideHeading(findingID int64) string {
	return fmt.Sprintf("### 实战验证补充 (Finding #%d)", findingID)
}

func findingPocHeading(findingID int64) string {
	return fmt.Sprintf("# --- 实战验证变种 (Finding #%d) ---", findingID)
}

func upsertMarkedSection(body, heading, block string) string {
	block = strings.TrimSpace(block)
	if block == "" {
		return body
	}
	section := heading + "\n\n" + block
	body = strings.TrimRight(body, "\n")
	start := strings.Index(body, heading)
	if start < 0 {
		if strings.TrimSpace(body) == "" {
			return section
		}
		return body + "\n\n" + section
	}
	end := len(body)
	rest := body[start+len(heading):]
	if i := indexNextSection(rest); i >= 0 {
		end = start + len(heading) + i
	}
	prefix := strings.TrimRight(body[:start], "\n")
	suffix := ""
	if end < len(body) {
		suffix = strings.TrimLeft(body[end:], "\n")
	}
	out := section
	if prefix != "" {
		out = prefix + "\n\n" + out
	}
	if suffix != "" {
		out += "\n\n" + suffix
	}
	return out
}

func indexNextSection(rest string) int {
	markers := []string{"\n### ", "\n# ---"}
	best := -1
	for _, m := range markers {
		if i := strings.Index(rest, m); i >= 0 && (best < 0 || i < best) {
			best = i
		}
	}
	return best
}

func mergePocSnippet(existing, incoming string, findingID int64) string {
	existing = strings.TrimSpace(existing)
	incoming = strings.TrimSpace(incoming)
	if incoming == "" {
		return existing
	}
	if existing == "" {
		return incoming
	}
	if strings.Contains(existing, incoming) {
		return existing
	}
	return upsertMarkedSection(existing, findingPocHeading(findingID), incoming)
}
