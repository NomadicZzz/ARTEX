package db

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// KB severity ranks. info is knowledge-only; findings do not use it.
const (
	KBSevCritical = "critical"
	KBSevHigh     = "high"
	KBSevMedium   = "medium"
	KBSevLow      = "low"
	KBSevInfo     = "info"
)

// KBReference is one public link stored on a knowledge entry.
type KBReference struct {
	Title string `json:"title,omitempty"`
	URL   string `json:"url"`
}

// KBEntry is one row of kb_entries. List queries leave the long text fields empty.
type KBEntry struct {
	ID                int64         `json:"id"`
	NKey              string        `json:"nkey"`
	ExternalID        string        `json:"external_id"`
	Aliases           []string      `json:"aliases"`
	SourceKeys        []string      `json:"source_keys"`
	Origin            string        `json:"origin"`
	Kind              string        `json:"kind"`
	VulnClass         string        `json:"vulnclass"`
	Severity          string        `json:"severity"`
	CVSS              float64       `json:"cvss_score,omitempty"`
	CWE               string        `json:"cwe_id,omitempty"`
	ActivelyExploited bool          `json:"actively_exploited"`
	Products          []string      `json:"products"`
	CPE               []string      `json:"cpe_list,omitempty"`
	AffectedVersions  string        `json:"affected_versions,omitempty"`
	Tags              []string      `json:"tags,omitempty"`
	Title             string        `json:"title"`
	Summary           string        `json:"summary"`
	DetectionGuide    string        `json:"detection_guide,omitempty"`
	PocSnippet        string        `json:"poc_snippet,omitempty"`
	Remediation       string        `json:"remediation,omitempty"`
	References        []KBReference `json:"references,omitempty"`
	Distilled         bool          `json:"distilled"`
	ContentHash       string        `json:"-"`
	ContentLocked     bool          `json:"content_locked"`
	PublishedAt       *time.Time    `json:"published_at,omitempty"`
	Enabled           bool          `json:"enabled"`
	CreatedAt         time.Time     `json:"created_at"`
	UpdatedAt         time.Time     `json:"updated_at"`
	HasPoC            bool          `json:"has_poc"`
	MatchedAssetCount int           `json:"matched_asset_count,omitempty"`
}

// KBSource is one configured intelligence feed.
type KBSource struct {
	ID              int64           `json:"id"`
	Key             string          `json:"key"`
	Name            string          `json:"name"`
	Kind            string          `json:"kind"`
	Enabled         bool            `json:"enabled"`
	SyncIntervalSec int             `json:"sync_interval_sec"`
	Config          json.RawMessage `json:"config"`
	Cursor          string          `json:"cursor"`
	LastSyncAt      *time.Time      `json:"last_sync_at,omitempty"`
	LastStatus      string          `json:"last_status"`
	LastError       string          `json:"last_error"`
	EntryCount      int             `json:"entry_count"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

// KBSyncRun is one sync attempt.
type KBSyncRun struct {
	ID            int64      `json:"id"`
	SourceID      int64      `json:"source_id"`
	SourceKey     string     `json:"source_key,omitempty"`
	TriggerType   string     `json:"trigger_type"`
	Status        string     `json:"status"`
	FetchedCount  int        `json:"fetched_count"`
	UpsertedCount int        `json:"upserted_count"`
	MergedCount   int        `json:"merged_count"`
	Error         string     `json:"error"`
	StartedAt     time.Time  `json:"started_at"`
	FinishedAt    *time.Time `json:"finished_at,omitempty"`
}

// KBQuery filters a knowledge search. Zero values mean "no filter".
type KBQuery struct {
	Q                 string
	Products          []string
	VulnClass         string
	MinSeverity       string
	Kind              string
	ActivelyExploited *bool
	HasPoC            *bool
	IncludeDisabled   bool
	MatchedProducts   []string // non-nil: restrict to entries whose products intersect this set
	Limit             int
	Offset            int
}

// KBAssetHit is one asset whose fingerprint intersects a knowledge entry.
type KBAssetHit struct {
	AssetID     int64    `json:"asset_id"`
	Type        string   `json:"type"`
	Label       string   `json:"label"`
	MatchedTech []string `json:"matched_tech"`
}

// KBFingerprint is one asset's raw technology strings before normalization.
type KBFingerprint struct {
	ID    int64
	Techs []string
}

// KBAssetMatch groups high-signal entries that hit one asset.
type KBAssetMatch struct {
	AssetID       int64     `json:"asset_id"`
	MatchedTech   []string  `json:"matched_tech"`
	HighVulnCount int       `json:"high_vuln_count"`
	TopEntries    []KBEntry `json:"top_entries"`
}

// KBStats is the knowledge home summary.
type KBStats struct {
	Total          int `json:"total"`
	KEV            int `json:"kev"`
	Methodology    int `json:"methodology"`
	WithPoC        int `json:"with_poc"`
	MatchedEntries int `json:"matched_entries"`
	MatchedAssets  int `json:"matched_assets"`
}

var cveIDPattern = regexp.MustCompile(`(?i)^CVE-\d{4}-\d{4,}$`)

// KBSeverityRank returns 0 for an unknown severity.
func KBSeverityRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case KBSevCritical:
		return 5
	case KBSevHigh:
		return 4
	case KBSevMedium:
		return 3
	case KBSevLow:
		return 2
	case KBSevInfo:
		return 1
	default:
		return 0
	}
}

// ValidKBSeverity reports whether s is a knowledge severity.
func ValidKBSeverity(s string) bool { return KBSeverityRank(s) > 0 }

// ValidKBKind reports whether s is a knowledge kind.
func ValidKBKind(s string) bool {
	switch s {
	case "cve", "poc", "methodology", "checklist":
		return true
	default:
		return false
	}
}

// CanonicalNKey picks the cross-source identity. A CVE always wins so NVD, KEV,
// GHSA, AVD and Nuclei land on the same row.
func CanonicalNKey(externalID, kind, title, fallback string) string {
	ext := strings.ToUpper(strings.TrimSpace(externalID))
	if cveIDPattern.MatchString(ext) {
		return "cve:" + ext
	}
	if strings.HasPrefix(ext, "GHSA-") {
		return "ghsa:" + ext
	}
	if strings.HasPrefix(ext, "AVD-") {
		return "avd:" + ext
	}
	if strings.TrimSpace(fallback) != "" && strings.Contains(fallback, ":") {
		return strings.TrimSpace(fallback)
	}
	base := title
	if base == "" {
		base = fallback
	}
	slug := slugToken(base)
	if slug == "" {
		slug = "entry"
	}
	switch kind {
	case "methodology", "checklist":
		return "method:" + slug
	case "poc":
		return "poc:" + slug
	default:
		return "kb:" + slug
	}
}

func slugToken(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	prevDash := false
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			prevDash = false
			continue
		}
		if !prevDash && b.Len() > 0 {
			b.WriteByte('-')
			prevDash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if utf8.RuneCountInString(out) > 80 {
		rs := []rune(out)
		out = string(rs[:80])
	}
	return out
}

func kbContentHash(e KBEntry) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\n%s\n%s\n%s\n%s\n%s\n%v\n%s",
		e.Title, e.Summary, e.DetectionGuide, e.PocSnippet, e.Remediation, e.Severity, e.ActivelyExploited, strings.Join(e.Products, ","))
	return hex.EncodeToString(h.Sum(nil))
}

func truncateRunes(s string, n int) string {
	if n <= 0 || utf8.RuneCountInString(s) <= n {
		return s
	}
	rs := []rune(s)
	return string(rs[:n])
}

// normalizeTags trims, lowercases, and dedupes tags in first-seen order.
// Product aliases stay off this path: a tag such as "ecology" is not a product token.
func normalizeTags(items []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range items {
		s = strings.ToLower(strings.TrimSpace(utf8Clean(s)))
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func unionStrings(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, list := range [][]string{a, b} {
		for _, s := range list {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			key := strings.ToLower(s)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, s)
		}
	}
	return out
}

func unionRefs(a, b []KBReference) []KBReference {
	seen := map[string]bool{}
	var out []KBReference
	for _, list := range [][]KBReference{a, b} {
		for _, r := range list {
			r.URL = strings.TrimSpace(r.URL)
			if r.URL == "" || seen[r.URL] {
				continue
			}
			seen[r.URL] = true
			out = append(out, r)
		}
	}
	return out
}

func preferText(existing, incoming string) string {
	existing = strings.TrimSpace(existing)
	incoming = strings.TrimSpace(incoming)
	if existing == "" {
		return incoming
	}
	if incoming == "" {
		return existing
	}
	exHan, inHan := containsHan(existing), containsHan(incoming)
	if inHan && !exHan {
		return incoming
	}
	if exHan && !inHan {
		return existing
	}
	if utf8.RuneCountInString(incoming) > utf8.RuneCountInString(existing) {
		return incoming
	}
	return existing
}

func fillIfEmpty(existing, incoming string) string {
	if strings.TrimSpace(existing) == "" {
		return strings.TrimSpace(incoming)
	}
	return existing
}

// MergeKBEntry folds incoming into existing. Locked rows keep human-authored
// prose; fingerprints, aliases and the KEV flag still accumulate.
func MergeKBEntry(existing, incoming KBEntry) KBEntry {
	out := existing
	out.SourceKeys = unionStrings(existing.SourceKeys, incoming.SourceKeys)
	out.Aliases = unionStrings(existing.Aliases, incoming.Aliases)
	promoteCVEIdentity(&out, existing, incoming)
	out.Products = NormalizeProducts(append(append([]string{}, existing.Products...), incoming.Products...))
	out.CPE = unionStrings(existing.CPE, incoming.CPE)
	out.Tags = normalizeTags(append(append([]string{}, existing.Tags...), incoming.Tags...))
	out.References = unionRefs(existing.References, incoming.References)
	out.ActivelyExploited = existing.ActivelyExploited || incoming.ActivelyExploited
	if incoming.PublishedAt != nil && (existing.PublishedAt == nil || incoming.PublishedAt.Before(*existing.PublishedAt)) {
		t := *incoming.PublishedAt
		out.PublishedAt = &t
	}
	if existing.ContentLocked {
		out.ContentHash = kbContentHash(out)
		return out
	}
	out.Title = preferText(existing.Title, incoming.Title)
	out.Summary = preferText(existing.Summary, incoming.Summary)
	out.DetectionGuide = fillIfEmpty(existing.DetectionGuide, incoming.DetectionGuide)
	out.PocSnippet = fillIfEmpty(existing.PocSnippet, incoming.PocSnippet)
	out.Remediation = fillIfEmpty(existing.Remediation, incoming.Remediation)
	out.AffectedVersions = fillIfEmpty(existing.AffectedVersions, incoming.AffectedVersions)
	out.VulnClass = fillIfEmpty(existing.VulnClass, incoming.VulnClass)
	out.CWE = fillIfEmpty(existing.CWE, incoming.CWE)
	if KBSeverityRank(incoming.Severity) > KBSeverityRank(existing.Severity) {
		out.Severity = incoming.Severity
	}
	if incoming.CVSS > existing.CVSS {
		out.CVSS = incoming.CVSS
	}
	if incoming.Distilled {
		out.Distilled = true
	}
	out.ContentHash = kbContentHash(out)
	return out
}

// sanitizeKBEntry drops bytes PostgreSQL text and jsonb refuse. Nuclei templates
// embed payloads that decode to NUL (0x00). That byte is valid UTF-8, but a text
// column rejects it with SQLSTATE 22021, and jsonb rejects the \u0000 escape.
func sanitizeKBEntry(in KBEntry) KBEntry {
	in.NKey = utf8Clean(in.NKey)
	in.ExternalID = utf8Clean(in.ExternalID)
	in.Origin = utf8Clean(in.Origin)
	in.Kind = utf8Clean(in.Kind)
	in.VulnClass = utf8Clean(in.VulnClass)
	in.Severity = utf8Clean(in.Severity)
	in.CWE = utf8Clean(in.CWE)
	in.AffectedVersions = utf8Clean(in.AffectedVersions)
	in.Title = utf8Clean(in.Title)
	in.Summary = utf8Clean(in.Summary)
	in.DetectionGuide = utf8Clean(in.DetectionGuide)
	in.PocSnippet = utf8Clean(in.PocSnippet)
	in.Remediation = utf8Clean(in.Remediation)
	in.Aliases = sanitizeStrings(in.Aliases)
	in.SourceKeys = sanitizeStrings(in.SourceKeys)
	in.Products = sanitizeStrings(in.Products)
	in.CPE = sanitizeStrings(in.CPE)
	in.Tags = sanitizeStrings(in.Tags)
	for i := range in.References {
		in.References[i].Title = utf8Clean(in.References[i].Title)
		in.References[i].URL = utf8Clean(in.References[i].URL)
	}
	return in
}

func sanitizeStrings(items []string) []string {
	if len(items) == 0 {
		return items
	}
	out := make([]string, len(items))
	for i, s := range items {
		out[i] = utf8Clean(s)
	}
	return out
}

func kbRefsJSON(refs []KBReference) string {
	if refs == nil {
		refs = []KBReference{}
	}
	raw, err := json.Marshal(refs)
	if err != nil {
		return "[]"
	}
	return string(jsonbClean(raw))
}

func prepareKBEntry(in KBEntry) (KBEntry, error) {
	in = sanitizeKBEntry(in)
	in.Title = truncateRunes(strings.TrimSpace(in.Title), 500)
	in.Summary = truncateRunes(strings.TrimSpace(in.Summary), 4000)
	in.DetectionGuide = truncateRunes(in.DetectionGuide, 20000)
	in.PocSnippet = truncateRunes(in.PocSnippet, 20000)
	in.Remediation = truncateRunes(in.Remediation, 8000)
	in.AffectedVersions = truncateRunes(strings.TrimSpace(in.AffectedVersions), 2000)
	in.ExternalID = strings.TrimSpace(in.ExternalID)
	if cveIDPattern.MatchString(in.ExternalID) {
		in.ExternalID = strings.ToUpper(in.ExternalID)
	}
	in.Kind = strings.ToLower(strings.TrimSpace(in.Kind))
	if !ValidKBKind(in.Kind) {
		if in.ExternalID != "" && cveIDPattern.MatchString(in.ExternalID) {
			in.Kind = "cve"
		} else {
			in.Kind = "methodology"
		}
	}
	in.Severity = strings.ToLower(strings.TrimSpace(in.Severity))
	if !ValidKBSeverity(in.Severity) {
		in.Severity = KBSevInfo
	}
	in.Origin = strings.TrimSpace(in.Origin)
	switch in.Origin {
	case "synced", "manual", "finding_distilled", "agent":
	default:
		in.Origin = "synced"
	}
	if in.Origin == "manual" || in.Origin == "finding_distilled" || in.Origin == "agent" {
		in.ContentLocked = true
	}
	in.NKey = CanonicalNKey(in.ExternalID, in.Kind, in.Title, in.NKey)
	in.Products = NormalizeProducts(in.Products)
	in.Aliases = unionStrings(nil, in.Aliases)
	in.SourceKeys = unionStrings(nil, in.SourceKeys)
	in.Tags = normalizeTags(in.Tags)
	in.CPE = unionStrings(nil, in.CPE)
	if in.References == nil {
		in.References = []KBReference{}
	}
	in.VulnClass = truncateRunes(strings.TrimSpace(in.VulnClass), 120)
	in.CWE = truncateRunes(strings.TrimSpace(in.CWE), 40)
	in.ContentHash = kbContentHash(in)
	if in.Title == "" && in.ExternalID == "" {
		return in, fmt.Errorf("title 或 external_id 至少填一个")
	}
	if in.Title == "" {
		in.Title = in.ExternalID
	}
	return in, nil
}

func kbOriginLocked(origin string) bool {
	return origin == "manual" || origin == "finding_distilled" || origin == "agent"
}

// promoteCVEIdentity retargets a merged row onto cve:CVE-... when any side carries a CVE.
func promoteCVEIdentity(out *KBEntry, existing, incoming KBEntry) {
	cve := firstCVE(incoming.ExternalID, existing.ExternalID)
	if cve == "" {
		for _, alias := range append(append([]string{}, incoming.Aliases...), existing.Aliases...) {
			if id := firstCVE(alias); id != "" {
				cve = id
				break
			}
		}
	}
	if cve != "" {
		if out.ExternalID != "" && !strings.EqualFold(out.ExternalID, cve) {
			out.Aliases = unionStrings(out.Aliases, []string{out.ExternalID})
		}
		if incoming.ExternalID != "" && !strings.EqualFold(incoming.ExternalID, cve) {
			out.Aliases = unionStrings(out.Aliases, []string{incoming.ExternalID})
		}
		out.ExternalID = cve
		out.NKey = "cve:" + cve
		out.Kind = "cve"
		return
	}
	if incoming.ExternalID != "" && strings.TrimSpace(existing.ExternalID) == "" {
		out.ExternalID = strings.TrimSpace(incoming.ExternalID)
		return
	}
	if incoming.ExternalID != "" && !strings.EqualFold(incoming.ExternalID, existing.ExternalID) {
		out.Aliases = unionStrings(out.Aliases, []string{incoming.ExternalID})
	}
}

func firstCVE(ids ...string) string {
	for _, id := range ids {
		id = strings.ToUpper(strings.TrimSpace(id))
		if cveIDPattern.MatchString(id) {
			return id
		}
	}
	return ""
}

const kbSelectCols = `id, nkey, external_id, array_to_json(aliases)::text, array_to_json(source_keys)::text,
origin, kind, vulnclass, severity, cvss_score, cwe_id, actively_exploited,
array_to_json(products)::text, array_to_json(cpe_list)::text, affected_versions, array_to_json(tags)::text,
title, summary, detection_guide, poc_snippet, remediation, "references",
distilled, content_hash, content_locked, published_at, enabled, created_at, updated_at`

func scanKBEntry(sc interface{ Scan(...any) error }, withBody bool) (KBEntry, error) {
	var e KBEntry
	var aliases, sources, products, cpe, tags, refs string
	var cvss sql.NullFloat64
	var published sql.NullTime
	cols := []any{
		&e.ID, &e.NKey, &e.ExternalID, &aliases, &sources,
		&e.Origin, &e.Kind, &e.VulnClass, &e.Severity, &cvss, &e.CWE, &e.ActivelyExploited,
		&products, &cpe, &e.AffectedVersions, &tags,
		&e.Title, &e.Summary,
	}
	var guide, poc, remediation string
	cols = append(cols, &guide, &poc, &remediation, &refs)
	cols = append(cols, &e.Distilled, &e.ContentHash, &e.ContentLocked, &published, &e.Enabled, &e.CreatedAt, &e.UpdatedAt)
	if err := sc.Scan(cols...); err != nil {
		return e, err
	}
	e.Aliases = decodeJSONStrings(aliases)
	e.SourceKeys = decodeJSONStrings(sources)
	e.Products = decodeJSONStrings(products)
	e.CPE = decodeJSONStrings(cpe)
	e.Tags = decodeJSONStrings(tags)
	e.HasPoC = strings.TrimSpace(poc) != ""
	if withBody {
		e.DetectionGuide = guide
		e.PocSnippet = poc
		e.Remediation = remediation
		_ = json.Unmarshal([]byte(refs), &e.References)
	}
	if cvss.Valid {
		e.CVSS = cvss.Float64
	}
	if published.Valid {
		t := published.Time
		e.PublishedAt = &t
	}
	return e, nil
}

func decodeJSONStrings(raw string) []string {
	if raw == "" || raw == "null" {
		return []string{}
	}
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return []string{}
	}
	if out == nil {
		return []string{}
	}
	return out
}

func pgTextArray(items []string) string {
	return marshalStringArray(items)
}

func (d *DB) UpsertAndMergeKBEntry(in KBEntry) (KBEntry, bool, error) {
	prepared, err := prepareKBEntry(in)
	if err != nil {
		return KBEntry{}, false, err
	}
	tx, err := d.Begin()
	if err != nil {
		return KBEntry{}, false, err
	}
	defer tx.Rollback()

	existing, found, err := findKBForMerge(tx, prepared)
	if err != nil {
		return KBEntry{}, false, err
	}
	if !found {
		id, err := insertKBEntry(tx, prepared)
		if err != nil {
			return KBEntry{}, false, err
		}
		if err := tx.Commit(); err != nil {
			return KBEntry{}, false, err
		}
		prepared.ID = id
		prepared.HasPoC = strings.TrimSpace(prepared.PocSnippet) != ""
		return prepared, false, nil
	}
	merged := MergeKBEntry(existing, prepared)
	if merged.ContentHash == existing.ContentHash && sameStringSet(merged.SourceKeys, existing.SourceKeys) && merged.ActivelyExploited == existing.ActivelyExploited {
		if err := tx.Commit(); err != nil {
			return KBEntry{}, false, err
		}
		existing.HasPoC = strings.TrimSpace(existing.PocSnippet) != ""
		return existing, true, nil
	}
	if err := updateKBEntry(tx, merged); err != nil {
		return KBEntry{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return KBEntry{}, false, err
	}
	merged.HasPoC = strings.TrimSpace(merged.PocSnippet) != ""
	return merged, true, nil
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, s := range a {
		seen[strings.ToLower(s)]++
	}
	for _, s := range b {
		k := strings.ToLower(s)
		seen[k]--
		if seen[k] < 0 {
			return false
		}
	}
	return true
}

func findKBForMerge(tx *sql.Tx, in KBEntry) (KBEntry, bool, error) {
	ext := strings.TrimSpace(in.ExternalID)
	row := tx.QueryRow(`SELECT `+kbSelectCols+` FROM kb_entries
		WHERE nkey = $1
		   OR ($2 <> '' AND (external_id = $2 OR $2 = ANY(aliases) OR nkey = $3))
		ORDER BY (nkey = $1) DESC, id
		LIMIT 1
		FOR UPDATE`, in.NKey, ext, "cve:"+strings.ToUpper(ext))
	e, err := scanKBEntry(row, true)
	if err == sql.ErrNoRows {
		return KBEntry{}, false, nil
	}
	if err != nil {
		return KBEntry{}, false, err
	}
	return e, true, nil
}

func insertKBEntry(tx *sql.Tx, e KBEntry) (int64, error) {
	refs := kbRefsJSON(e.References)
	var published any
	if e.PublishedAt != nil {
		published = *e.PublishedAt
	}
	var cvss any
	if e.CVSS > 0 {
		cvss = e.CVSS
	}
	var id int64
	err := tx.QueryRow(`INSERT INTO kb_entries (
		nkey, external_id, aliases, source_keys, origin, kind, vulnclass, severity, cvss_score, cwe_id,
		actively_exploited, products, cpe_list, affected_versions, tags, title, summary, detection_guide,
		poc_snippet, remediation, "references", distilled, content_hash, content_locked, published_at, enabled)
		VALUES ($1,$2,$3::text[],$4::text[],$5,$6,$7,$8,$9,$10,$11,$12::text[],$13::text[],$14,$15::text[],$16,$17,$18,$19,$20,$21::jsonb,$22,$23,$24,$25,true)
		RETURNING id`,
		e.NKey, e.ExternalID, pgTextArray(e.Aliases), pgTextArray(e.SourceKeys), e.Origin, e.Kind, e.VulnClass, e.Severity, cvss, e.CWE,
		e.ActivelyExploited, pgTextArray(e.Products), pgTextArray(e.CPE), e.AffectedVersions, pgTextArray(e.Tags),
		e.Title, e.Summary, e.DetectionGuide, e.PocSnippet, e.Remediation, refs, e.Distilled, e.ContentHash, e.ContentLocked || kbOriginLocked(e.Origin), published,
	).Scan(&id)
	return id, err
}

func updateKBEntry(tx *sql.Tx, e KBEntry) error {
	refs := kbRefsJSON(e.References)
	var published any
	if e.PublishedAt != nil {
		published = *e.PublishedAt
	}
	var cvss any
	if e.CVSS > 0 {
		cvss = e.CVSS
	}
	_, err := tx.Exec(`UPDATE kb_entries SET
		nkey=$1, external_id=$2, aliases=$3::text[], source_keys=$4::text[], kind=$5, vulnclass=$6, severity=$7,
		cvss_score=$8, cwe_id=$9, actively_exploited=$10, products=$11::text[], cpe_list=$12::text[],
		affected_versions=$13, tags=$14::text[], title=$15, summary=$16, detection_guide=$17, poc_snippet=$18,
		remediation=$19, "references"=$20::jsonb, distilled=$21, content_hash=$22, published_at=$23
		WHERE id=$24`,
		e.NKey, e.ExternalID, pgTextArray(e.Aliases), pgTextArray(e.SourceKeys), e.Kind, e.VulnClass, e.Severity,
		cvss, e.CWE, e.ActivelyExploited, pgTextArray(e.Products), pgTextArray(e.CPE),
		e.AffectedVersions, pgTextArray(e.Tags), e.Title, e.Summary, e.DetectionGuide, e.PocSnippet,
		e.Remediation, refs, e.Distilled, e.ContentHash, published, e.ID)
	return err
}

// UpdateKBEntryContent replaces editable fields and locks them against sync.
func (d *DB) UpdateKBEntryContent(id int64, in KBEntry) (KBEntry, error) {
	cur, err := d.GetKBEntry(id)
	if err != nil || cur == nil {
		if cur == nil && err == nil {
			return KBEntry{}, sql.ErrNoRows
		}
		return KBEntry{}, err
	}
	cur.Title = in.Title
	cur.Summary = in.Summary
	cur.DetectionGuide = in.DetectionGuide
	cur.PocSnippet = in.PocSnippet
	cur.Remediation = in.Remediation
	cur.Severity = in.Severity
	cur.VulnClass = in.VulnClass
	cur.Kind = in.Kind
	cur.Products = in.Products
	cur.Tags = in.Tags
	cur.AffectedVersions = in.AffectedVersions
	cur.ExternalID = in.ExternalID
	if in.References != nil {
		cur.References = in.References
	}
	cur.Enabled = in.Enabled
	cur.ContentLocked = true
	prepared, err := prepareKBEntry(*cur)
	if err != nil {
		return KBEntry{}, err
	}
	prepared.ID = id
	prepared.NKey = cur.NKey // keep identity; prepare may rewrite nkey from a new external id
	if in.ExternalID != "" && cveIDPattern.MatchString(in.ExternalID) {
		prepared.NKey = CanonicalNKey(in.ExternalID, prepared.Kind, prepared.Title, cur.NKey)
	}
	prepared.ContentLocked = true
	prepared.Origin = cur.Origin
	tx, err := d.Begin()
	if err != nil {
		return KBEntry{}, err
	}
	defer tx.Rollback()
	refs := kbRefsJSON(prepared.References)
	_, err = tx.Exec(`UPDATE kb_entries SET
		nkey=$1, external_id=$2, products=$3::text[], tags=$4::text[], kind=$5, vulnclass=$6, severity=$7,
		affected_versions=$8, title=$9, summary=$10, detection_guide=$11, poc_snippet=$12, remediation=$13,
		"references"=$14::jsonb, content_hash=$15, content_locked=true, enabled=$16
		WHERE id=$17`,
		prepared.NKey, prepared.ExternalID, pgTextArray(prepared.Products), pgTextArray(prepared.Tags),
		prepared.Kind, prepared.VulnClass, prepared.Severity, prepared.AffectedVersions, prepared.Title,
		prepared.Summary, prepared.DetectionGuide, prepared.PocSnippet, prepared.Remediation, refs,
		prepared.ContentHash, prepared.Enabled, id)
	if err != nil {
		return KBEntry{}, err
	}
	if err := tx.Commit(); err != nil {
		return KBEntry{}, err
	}
	got, err := d.GetKBEntry(id)
	if err != nil || got == nil {
		return KBEntry{}, err
	}
	return *got, nil
}

func (d *DB) GetKBEntry(id int64) (*KBEntry, error) {
	row := d.QueryRow(`SELECT `+kbSelectCols+` FROM kb_entries WHERE id=$1`, id)
	e, err := scanKBEntry(row, true)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	e.HasPoC = strings.TrimSpace(e.PocSnippet) != ""
	return &e, nil
}

func (d *DB) GetKBEntryByExternalID(externalID string) (*KBEntry, error) {
	ext := strings.TrimSpace(externalID)
	if cveIDPattern.MatchString(ext) {
		ext = strings.ToUpper(ext)
	}
	row := d.QueryRow(`SELECT `+kbSelectCols+` FROM kb_entries
		WHERE external_id=$1 OR $1 = ANY(aliases) OR nkey=$2
		ORDER BY (external_id=$1) DESC, id LIMIT 1`, ext, "cve:"+ext)
	e, err := scanKBEntry(row, true)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	e.HasPoC = strings.TrimSpace(e.PocSnippet) != ""
	return &e, nil
}

func (d *DB) ListKBEntriesByIDs(ids []int64) ([]KBEntry, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := d.Query(`SELECT `+kbSelectCols+` FROM kb_entries WHERE id = ANY($1::bigint[])`, int64Array(ids))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KBEntry
	for rows.Next() {
		e, err := scanKBEntry(rows, true)
		if err != nil {
			return nil, err
		}
		e.HasPoC = strings.TrimSpace(e.PocSnippet) != ""
		out = append(out, e)
	}
	return out, rows.Err()
}

func int64Array(ids []int64) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = fmt.Sprintf("%d", id)
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func (d *DB) DeleteKBEntry(id int64) error {
	_, err := d.Exec(`DELETE FROM kb_entries WHERE id=$1`, id)
	return err
}

// ApplyKBDistill writes a distilled detection guide without locking the row against later sync.
func (d *DB) ApplyKBDistill(id int64, summary, guide, vulnclass string, products []string) error {
	if id <= 0 || strings.TrimSpace(guide) == "" {
		return nil
	}
	products = NormalizeProducts(sanitizeStrings(products))
	_, err := d.Exec(`UPDATE kb_entries SET
		detection_guide=$1,
		summary = CASE WHEN $2 <> '' AND btrim(summary) = '' THEN $2 ELSE summary END,
		vulnclass = CASE WHEN $3 <> '' AND btrim(vulnclass) = '' THEN $3 ELSE vulnclass END,
		products = CASE WHEN cardinality(products) = 0 AND cardinality($4::text[]) > 0 THEN $4::text[] ELSE products END,
		distilled = true
		WHERE id=$5`,
		truncateRunes(utf8Clean(guide), 20000), truncateRunes(utf8Clean(summary), 4000), truncateRunes(utf8Clean(vulnclass), 120), pgTextArray(products), id)
	return err
}

// SetKBDetectionGuide fills empty prose from an optional distill pass and does not lock the row.
func (d *DB) SetKBDetectionGuide(id int64, summary, guide, vulnclass string, products []string) error {
	if id <= 0 || strings.TrimSpace(guide) == "" {
		return nil
	}
	products = NormalizeProducts(sanitizeStrings(products))
	_, err := d.Exec(`UPDATE kb_entries SET
		detection_guide = CASE WHEN btrim(detection_guide) = '' THEN $1 ELSE detection_guide END,
		summary = CASE WHEN btrim(summary) = '' THEN $2 ELSE summary END,
		vulnclass = CASE WHEN btrim(vulnclass) = '' THEN $3 ELSE vulnclass END,
		products = CASE WHEN cardinality(products) = 0 AND cardinality($4::text[]) > 0 THEN $4::text[] ELSE products END,
		distilled = true
		WHERE id=$5 AND NOT content_locked`,
		truncateRunes(utf8Clean(guide), 20000), truncateRunes(utf8Clean(summary), 4000), truncateRunes(utf8Clean(vulnclass), 120), pgTextArray(products), id)
	return err
}

// SearchKBEntries runs the hybrid search. Total is the unpaged match count.
func (d *DB) SearchKBEntries(q KBQuery) ([]KBEntry, int, error) {
	where, args, qn := q.where()
	var total int
	if err := d.QueryRow(`SELECT count(*) FROM kb_entries e WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	limit := q.Limit
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	offset := q.Offset
	if offset < 0 {
		offset = 0
	}
	args = append(args, limit, offset)
	rank := "0::float4"
	if qn > 0 {
		rank = fmt.Sprintf(`ts_rank(COALESCE(e.search_tsv, ''::tsvector), plainto_tsquery('simple', $%d))`, qn)
	}
	rows, err := d.Query(fmt.Sprintf(`SELECT `+kbSelectCols+`
		FROM kb_entries e WHERE %s
		ORDER BY e.actively_exploited DESC, (e.poc_snippet <> '') DESC,
			CASE lower(e.severity) WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 WHEN 'info' THEN 1 ELSE 0 END DESC,
			%s DESC, e.published_at DESC NULLS LAST, e.id DESC
		LIMIT $%d OFFSET $%d`, where, rank, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []KBEntry
	for rows.Next() {
		e, err := scanKBEntry(rows, false)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}
