package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

// where returns the SQL predicate, args, and the 1-based index of the raw
// full-text query (0 when q is empty).
func (q KBQuery) where() (string, []any, int) {
	var conds []string
	var args []any
	qn := 0
	if !q.IncludeDisabled {
		conds = append(conds, "e.enabled")
	}
	if s := strings.TrimSpace(q.Q); s != "" {
		args = append(args, s)
		qn = len(args)
		args = append(args, "%"+escapeLike(s)+"%")
		ln := len(args)
		conds = append(conds, fmt.Sprintf(`(
			e.external_id ILIKE $%d ESCAPE '\'
			OR e.title ILIKE $%d ESCAPE '\'
			OR e.summary ILIKE $%d ESCAPE '\'
			OR COALESCE(e.search_tsv, ''::tsvector) @@ plainto_tsquery('simple', $%d)
			OR EXISTS (SELECT 1 FROM unnest(e.aliases) a WHERE a ILIKE $%d ESCAPE '\')
			OR EXISTS (SELECT 1 FROM unnest(e.products) p WHERE p ILIKE $%d ESCAPE '\')
			OR upper(e.external_id) = upper($%d)
		)`, ln, ln, ln, qn, ln, ln, qn))
	}
	if len(q.Products) > 0 {
		args = append(args, pgTextArray(NormalizeProducts(q.Products)))
		conds = append(conds, fmt.Sprintf("e.products && $%d::text[]", len(args)))
	}
	if q.MatchedProducts != nil {
		if len(q.MatchedProducts) == 0 {
			conds = append(conds, "FALSE")
		} else {
			args = append(args, pgTextArray(q.MatchedProducts))
			conds = append(conds, fmt.Sprintf("e.products && $%d::text[]", len(args)))
		}
	}
	if v := strings.TrimSpace(q.VulnClass); v != "" {
		args = append(args, v)
		conds = append(conds, fmt.Sprintf("e.vulnclass = $%d", len(args)))
	}
	if r := KBSeverityRank(q.MinSeverity); r > 0 {
		args = append(args, r)
		conds = append(conds, fmt.Sprintf(`CASE lower(e.severity) WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 WHEN 'info' THEN 1 ELSE 0 END >= $%d`, len(args)))
	}
	if k := strings.TrimSpace(q.Kind); k != "" && k != "all" {
		args = append(args, k)
		conds = append(conds, fmt.Sprintf("e.kind = $%d", len(args)))
	}
	if q.ActivelyExploited != nil {
		args = append(args, *q.ActivelyExploited)
		conds = append(conds, fmt.Sprintf("e.actively_exploited = $%d", len(args)))
	}
	if q.HasPoC != nil {
		if *q.HasPoC {
			conds = append(conds, "e.poc_snippet <> ''")
		} else {
			conds = append(conds, "e.poc_snippet = ''")
		}
	}
	if sk := strings.TrimSpace(q.SourceKey); sk != "" {
		args = append(args, sk)
		n := len(args)
		conds = append(conds, fmt.Sprintf("(e.origin = $%d OR $%d = ANY(COALESCE(e.source_keys, ARRAY[]::text[])))", n, n))
	}
	if len(conds) == 0 {
		return "TRUE", args, qn
	}
	return strings.Join(conds, " AND "), args, qn
}

func (d *DB) ListKBSources() ([]KBSource, error) {
	rows, err := d.Query(`SELECT id, key, name, kind, enabled, sync_interval_sec, config, cursor,
		last_sync_at, last_status, last_error, entry_count, created_at, updated_at
		FROM kb_sources ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KBSource
	for rows.Next() {
		s, err := scanKBSource(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (d *DB) GetKBSource(id int64) (*KBSource, error) {
	row := d.QueryRow(`SELECT id, key, name, kind, enabled, sync_interval_sec, config, cursor,
		last_sync_at, last_status, last_error, entry_count, created_at, updated_at
		FROM kb_sources WHERE id=$1`, id)
	s, err := scanKBSource(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (d *DB) GetKBSourceByKey(key string) (*KBSource, error) {
	row := d.QueryRow(`SELECT id, key, name, kind, enabled, sync_interval_sec, config, cursor,
		last_sync_at, last_status, last_error, entry_count, created_at, updated_at
		FROM kb_sources WHERE key=$1`, key)
	s, err := scanKBSource(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func scanKBSource(sc interface{ Scan(...any) error }) (KBSource, error) {
	var s KBSource
	var cfg []byte
	var last sql.NullTime
	err := sc.Scan(&s.ID, &s.Key, &s.Name, &s.Kind, &s.Enabled, &s.SyncIntervalSec, &cfg, &s.Cursor,
		&last, &s.LastStatus, &s.LastError, &s.EntryCount, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		return s, err
	}
	if len(cfg) == 0 {
		cfg = []byte(`{}`)
	}
	s.Config = cfg
	if last.Valid {
		t := last.Time
		s.LastSyncAt = &t
	}
	return s, nil
}

func (d *DB) CreateKBSource(s KBSource) (*KBSource, error) {
	if strings.TrimSpace(s.Key) == "" || strings.TrimSpace(s.Kind) == "" {
		return nil, fmt.Errorf("key 和 kind 必填")
	}
	if len(s.Config) == 0 {
		s.Config = []byte(`{}`)
	}
	if s.SyncIntervalSec <= 0 {
		s.SyncIntervalSec = 86400
	}
	var id int64
	err := d.QueryRow(`INSERT INTO kb_sources(key, name, kind, enabled, sync_interval_sec, config)
		VALUES ($1,$2,$3,$4,$5,$6::jsonb) RETURNING id`,
		s.Key, s.Name, s.Kind, s.Enabled, s.SyncIntervalSec, string(s.Config)).Scan(&id)
	if err != nil {
		return nil, err
	}
	return d.GetKBSource(id)
}

func (d *DB) UpdateKBSource(id int64, s KBSource) (*KBSource, error) {
	cur, err := d.GetKBSource(id)
	if err != nil || cur == nil {
		if cur == nil && err == nil {
			return nil, sql.ErrNoRows
		}
		return nil, err
	}
	if len(s.Config) == 0 {
		s.Config = cur.Config
	}
	if s.SyncIntervalSec <= 0 {
		s.SyncIntervalSec = cur.SyncIntervalSec
	}
	if strings.TrimSpace(s.Name) == "" {
		s.Name = cur.Name
	}
	_, err = d.Exec(`UPDATE kb_sources SET name=$1, enabled=$2, sync_interval_sec=$3, config=$4::jsonb WHERE id=$5`,
		s.Name, s.Enabled, s.SyncIntervalSec, string(s.Config), id)
	if err != nil {
		return nil, err
	}
	return d.GetKBSource(id)
}

func (d *DB) DeleteKBSource(id int64) error {
	var key string
	err := d.QueryRow(`SELECT key FROM kb_sources WHERE id=$1`, id).Scan(&key)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	switch key {
	case "cisa_kev", "nuclei_templates", "nvd_cve", "github_ghsa", "aliyun_avd", "seebug_rss", "custom_git_kb":
		return fmt.Errorf("内置源不可删除，请停用")
	}
	_, err = d.Exec(`DELETE FROM kb_sources WHERE id=$1`, id)
	return err
}

func (d *DB) MarkKBSourceSync(id int64, status, errText, cursor string, entryCount int) error {
	_, err := d.Exec(`UPDATE kb_sources SET last_status=$1, last_error=$2, cursor=$3, entry_count=$4, last_sync_at=now() WHERE id=$5`,
		status, truncateRunes(errText, 2000), cursor, entryCount, id)
	return err
}

func (d *DB) RefreshKBSourceCount(id int64, key string) (int, error) {
	var n int
	err := d.QueryRow(`SELECT count(*) FROM kb_entries WHERE $1 = ANY(source_keys)`, key).Scan(&n)
	if err != nil {
		return 0, err
	}
	_, err = d.Exec(`UPDATE kb_sources SET entry_count=$1 WHERE id=$2`, n, id)
	return n, err
}

func (d *DB) StartKBSyncRun(sourceID int64, trigger string) (int64, error) {
	var id int64
	err := d.QueryRow(`INSERT INTO kb_sync_runs(source_id, trigger_type, status) VALUES ($1,$2,'running') RETURNING id`,
		sourceID, trigger).Scan(&id)
	return id, err
}

func (d *DB) FinishKBSyncRun(id int64, status string, fetched, upserted, merged, skipped int, errText string) error {
	_, err := d.Exec(`UPDATE kb_sync_runs SET status=$1, fetched_count=$2, upserted_count=$3, merged_count=$4, skipped_count=$5, error=$6, finished_at=now() WHERE id=$7`,
		status, fetched, upserted, merged, skipped, truncateRunes(errText, 2000), id)
	return err
}

func (d *DB) ListKBSyncRuns(sourceID int64, limit int) ([]KBSyncRun, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	q := `SELECT r.id, r.source_id, s.key, r.trigger_type, r.status, r.fetched_count, r.upserted_count, r.merged_count, r.skipped_count, r.error, r.started_at, r.finished_at
		FROM kb_sync_runs r JOIN kb_sources s ON s.id = r.source_id`
	var args []any
	if sourceID > 0 {
		q += ` WHERE r.source_id=$1`
		args = append(args, sourceID)
	}
	args = append(args, limit)
	q += fmt.Sprintf(` ORDER BY r.id DESC LIMIT $%d`, len(args))
	rows, err := d.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KBSyncRun
	for rows.Next() {
		var r KBSyncRun
		var finished sql.NullTime
		if err := rows.Scan(&r.ID, &r.SourceID, &r.SourceKey, &r.TriggerType, &r.Status, &r.FetchedCount, &r.UpsertedCount, &r.MergedCount, &r.SkippedCount, &r.Error, &r.StartedAt, &finished); err != nil {
			return nil, err
		}
		if finished.Valid {
			t := finished.Time
			r.FinishedAt = &t
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AssetFingerprintIndex maps a normalized product token to the assets that carry it.
func (d *DB) AssetFingerprintIndex() (map[string][]int64, error) {
	rows, err := d.Query(`SELECT id, array_to_json(technologies)::text, COALESCE(service_name,''), COALESCE(app_name,'')
		FROM assets
		WHERE cardinality(technologies) > 0 OR COALESCE(service_name,'') <> '' OR COALESCE(app_name,'') <> ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	idx := map[string][]int64{}
	for rows.Next() {
		var id int64
		var techs, service, app string
		if err := rows.Scan(&id, &techs, &service, &app); err != nil {
			return nil, err
		}
		for _, tok := range AssetFingerprints(decodeJSONStrings(techs), service, app) {
			idx[tok] = append(idx[tok], id)
		}
	}
	return idx, rows.Err()
}

// FingerprintSet is the deduped product vocabulary present on current assets.
func FingerprintSet(idx map[string][]int64) []string {
	out := make([]string, 0, len(idx))
	for k := range idx {
		out = append(out, k)
	}
	return out
}

// CountAssetHits reports how many entries and distinct assets intersect.
func CountAssetHits(entries []KBEntry, idx map[string][]int64) (entriesHit, assetsHit int) {
	assets := map[int64]bool{}
	for _, e := range entries {
		hit := map[int64]bool{}
		for _, p := range e.Products {
			for _, id := range idx[p] {
				hit[id] = true
				assets[id] = true
			}
		}
		if len(hit) > 0 {
			entriesHit++
		}
	}
	return entriesHit, len(assets)
}

// CountMatchedAssets is the number of distinct assets whose fingerprints hit products.
func CountMatchedAssets(products []string, idx map[string][]int64) int {
	ids, _ := assetIDsForProducts(products, idx)
	return len(ids)
}

func assetIDsForProducts(products []string, idx map[string][]int64) (ids []int64, matched []string) {
	seen := map[int64]bool{}
	used := map[string]bool{}
	for _, p := range products {
		list := idx[p]
		if len(list) == 0 {
			continue
		}
		used[p] = true
		for _, id := range list {
			if seen[id] {
				continue
			}
			seen[id] = true
			ids = append(ids, id)
		}
	}
	for p := range used {
		matched = append(matched, p)
	}
	return ids, matched
}

// MatchedAssetsForEntry returns up to limit assets that hit this entry.
func (d *DB) MatchedAssetsForEntry(products []string, idx map[string][]int64, limit int) ([]KBAssetHit, error) {
	ids, _ := assetIDsForProducts(products, idx)
	if len(ids) == 0 {
		return nil, nil
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if len(ids) > limit {
		ids = ids[:limit]
	}
	rows, err := d.Query(`SELECT id, type, COALESCE(domain,''), COALESCE(url,''), COALESCE(ip,''), COALESCE(app_name,''), COALESCE(service_name,''), COALESCE(method,'')
		FROM assets WHERE id = ANY($1::bigint[])`, int64Array(ids))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	prodSet := map[string]bool{}
	for _, p := range products {
		prodSet[p] = true
	}
	var out []KBAssetHit
	for rows.Next() {
		var id int64
		var typ, domain, url, ip, app, service, method string
		if err := rows.Scan(&id, &typ, &domain, &url, &ip, &app, &service, &method); err != nil {
			return nil, err
		}
		label := assetHitLabel(typ, domain, url, ip, app, service, method)
		var matched []string
		for _, tok := range AssetFingerprints(nil, service, app) {
			if prodSet[tok] {
				matched = append(matched, tok)
			}
		}
		// technologies are not in this query; the entry products that indexed this asset are the match.
		if len(matched) == 0 {
			for _, p := range products {
				for _, aid := range idx[p] {
					if aid == id {
						matched = append(matched, p)
						break
					}
				}
			}
		}
		out = append(out, KBAssetHit{AssetID: id, Type: typ, Label: label, MatchedTech: matched})
	}
	return out, rows.Err()
}

func assetHitLabel(typ, domain, url, ip, app, service, method string) string {
	switch {
	case url != "":
		if method != "" {
			return method + " " + url
		}
		return url
	case domain != "":
		return domain
	case ip != "":
		return ip
	case app != "":
		return app
	case service != "":
		return service
	default:
		return typ
	}
}

// kbTierExpr ranks an entry's provenance. Tier 0 is what this platform actually
// saw work — a distilled finding, or a human/agent write. Everything else came
// from a public feed and is only a lead.
const kbTierExpr = `(CASE WHEN e.origin IN ('finding_distilled', 'manual', 'agent')
	OR COALESCE(e.source_keys, ARRAY[]::text[]) @> ARRAY['finding_distilled']::text[]
	THEN 1 ELSE 0 END)`

// kbTierOrder is the shared ORDER BY prefix: internal experience first, then
// known-exploited, then entries that carry a PoC, then severity.
const kbTierOrder = kbTierExpr + ` DESC,
	e.actively_exploited DESC,
	(CASE WHEN COALESCE(BTRIM(e.poc_snippet), '') <> '' THEN 1 ELSE 0 END) DESC,
	CASE lower(e.severity) WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 WHEN 'info' THEN 1 ELSE 0 END DESC`

// kbHighSignal projects only the columns kb_hints needs.
const kbHighSignal = `id, nkey, external_id, title, severity, actively_exploited,
	(COALESCE(BTRIM(poc_snippet), '') <> '') , ` + kbTierExpr + `, array_to_json(products)::text`

// kbMatchLimit caps the candidate pool pulled for one collision pass.
const kbMatchLimit = 200

// MatchAssetsAgainstKB returns the entries worth surfacing next to each asset.
//
// A specific component token (fastjson, nacos, weaver-ecology) collides with
// anything high-signal: internal experience, a KEV row, or a row with a PoC. A
// bare stack foundation (nginx, java, mysql) only collides with internal
// experience, so identifying "nginx" never drags in forty old public CVEs.
// HighVulnCount is the full hit count; TopEntries is capped at limitPer.
func (d *DB) MatchAssetsAgainstKB(assets []KBFingerprint, limitPer int) ([]KBAssetMatch, error) {
	if limitPer <= 0 {
		limitPer = 3
	}
	type fp struct {
		id       int64
		specific []string
		broad    []string
	}
	var items []fp
	union := map[string]bool{}
	for _, a := range assets {
		specific, broad := SplitSpecificAndBroadProducts(a.Techs)
		if len(specific) == 0 && len(broad) == 0 {
			continue
		}
		items = append(items, fp{id: a.ID, specific: specific, broad: broad})
		for _, t := range append(append([]string{}, specific...), broad...) {
			union[t] = true
		}
	}
	if len(union) == 0 {
		return nil, nil
	}
	keys := make([]string, 0, len(union))
	for k := range union {
		keys = append(keys, k)
	}
	rows, err := d.Query(`SELECT `+kbHighSignal+`
		FROM kb_entries e
		WHERE e.enabled AND e.products && $1::text[]
		ORDER BY `+kbTierOrder+`, e.id DESC
		LIMIT $2`, pgTextArray(keys), kbMatchLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type foundRow struct {
		e           KBEntry
		products    []string
		internal    bool
	}
	var found []foundRow
	for rows.Next() {
		var e KBEntry
		var products string
		var internal bool
		if err := rows.Scan(&e.ID, &e.NKey, &e.ExternalID, &e.Title, &e.Severity,
			&e.ActivelyExploited, &e.HasPoC, &internal, &products); err != nil {
			return nil, err
		}
		ps := decodeJSONStrings(products)
		e.Products = ps
		found = append(found, foundRow{e: e, products: ps, internal: internal})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var out []KBAssetMatch
	for _, it := range items {
		specific := map[string]bool{}
		for _, t := range it.specific {
			specific[t] = true
		}
		broad := map[string]bool{}
		for _, t := range it.broad {
			broad[t] = true
		}
		var matched []string
		var tops []KBEntry
		hits := 0
		for _, f := range found {
			hit, local := matchRow(f.products, f.e, f.internal, specific, broad)
			if !hit {
				continue
			}
			hits++
			matched = unionStrings(matched, local)
			if len(tops) < limitPer {
				tops = append(tops, f.e)
			}
		}
		if hits == 0 {
			continue
		}
		out = append(out, KBAssetMatch{AssetID: it.id, MatchedTech: matched, HighVulnCount: hits, TopEntries: tops})
	}
	return out, nil
}

// matchRow decides whether one candidate is worth showing for an asset, and which
// of its products caused the hit.
func matchRow(products []string, e KBEntry, internal bool, specific, broad map[string]bool) (bool, []string) {
	var local []string
	hit := false
	for _, p := range products {
		switch {
		case specific[p] && (internal || e.ActivelyExploited || e.HasPoC):
			hit = true
		case broad[p] && internal:
			hit = true
		default:
			continue
		}
		local = append(local, p)
	}
	return hit, local
}

// KBFindingRef is a finding that cites a knowledge entry.
type KBFindingRef struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	VulnClass string `json:"vulnclass"`
	Severity  string `json:"severity"`
	Summary   string `json:"summary"`
}

func (d *DB) RelatedFindingsForKB(entryID int64, limit int) ([]KBFindingRef, error) {
	if limit <= 0 {
		limit = 20
	}
	raw, _ := json.Marshal([]int64{entryID})
	rows, err := d.Query(`SELECT id, COALESCE(name,''), vulnclass, severity, summary
		FROM findings WHERE kb_entry_ids @> $1::jsonb
		ORDER BY id DESC LIMIT $2`, string(raw), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KBFindingRef
	for rows.Next() {
		var f KBFindingRef
		if err := rows.Scan(&f.ID, &f.Name, &f.VulnClass, &f.Severity, &f.Summary); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (d *DB) AddFindingKBEntry(findingID, entryID int64) error {
	if findingID <= 0 || entryID <= 0 {
		return fmt.Errorf("id 无效")
	}
	_, err := d.Exec(`UPDATE findings SET kb_entry_ids = (
		SELECT COALESCE(jsonb_agg(DISTINCT x), '[]'::jsonb)
		FROM (
			SELECT jsonb_array_elements(kb_entry_ids) AS x
			UNION ALL
			SELECT to_jsonb($2::bigint)
		) s
	) WHERE id=$1`, findingID, entryID)
	return err
}

func (d *DB) KBEntryCounts() (total, kev, methodology, withPoC int, err error) {
	err = d.QueryRow(`SELECT
		count(*) FILTER (WHERE enabled),
		count(*) FILTER (WHERE enabled AND actively_exploited),
		count(*) FILTER (WHERE enabled AND kind IN ('methodology','checklist')),
		count(*) FILTER (WHERE enabled AND poc_snippet <> '')
		FROM kb_entries`).Scan(&total, &kev, &methodology, &withPoC)
	return
}

// ListKBProductIndex returns enabled entries with only the product column filled.
func (d *DB) ListKBProductIndex() ([]KBEntry, error) {
	rows, err := d.Query(`SELECT id, array_to_json(products)::text FROM kb_entries WHERE enabled`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KBEntry
	for rows.Next() {
		var e KBEntry
		var products string
		if err := rows.Scan(&e.ID, &products); err != nil {
			return nil, err
		}
		e.Products = decodeJSONStrings(products)
		out = append(out, e)
	}
	return out, rows.Err()
}

// DueKBSources returns enabled sources whose interval has elapsed.
func (d *DB) DueKBSources(now time.Time) ([]KBSource, error) {
	all, err := d.ListKBSources()
	if err != nil {
		return nil, err
	}
	var due []KBSource
	for _, s := range all {
		if !s.Enabled || s.SyncIntervalSec <= 0 {
			continue
		}
		if s.LastSyncAt == nil || now.Sub(*s.LastSyncAt) >= time.Duration(s.SyncIntervalSec)*time.Second {
			due = append(due, s)
		}
	}
	return due, nil
}
