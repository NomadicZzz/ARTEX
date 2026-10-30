package kb

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
)

// Distiller optionally fills an empty detection guide. It must not invent exploit chains.
type Distiller func(ctx context.Context, entry db.KBEntry) (DistillFields, error)

// Syncer pulls due sources one at a time. A failure in one source does not stop the others.
type Syncer struct {
	DB       *db.DB
	Proxy    func() string
	Distill  Distiller
	Interval time.Duration

	mu      sync.Mutex
	running map[string]struct{}
}

func NewSyncer(database *db.DB, proxy func() string) *Syncer {
	return &Syncer{DB: database, Proxy: proxy, Interval: time.Minute, running: map[string]struct{}{}}
}

func (s *Syncer) client() *Client {
	return &Client{Proxy: s.Proxy}
}

// Run ticks until ctx is cancelled. Before the first tick it purges the hollow
// rows earlier syncs left behind.
func (s *Syncer) Run(ctx context.Context) {
	interval := s.Interval
	if interval <= 0 {
		interval = time.Minute
	}
	s.purgeHollow()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	s.tick(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.tick(ctx)
		}
	}
}

// purgeHollow deletes synced rows that only restate a public advisory. It runs
// once at startup; a failure is silent because the next run retries it.
func (s *Syncer) purgeHollow() {
	if s.DB == nil {
		return
	}
	n, err := s.DB.PurgeHollowSyncedCVEs(db.KBHollowFilter{HollowGuides: DefaultHollowGuides()})
	if err != nil || n <= 0 {
		return
	}
	_ = s.DB.RefreshAllKBSourceCounts()
	log.Printf("[kb] 启动清理空壳同步条目 %d 条", n)
}

// syncPriority orders a due batch so the PoC and KEV floor is laid down before
// the descriptive feeds try to enrich it. Sources outside the list keep their
// configured order after the listed ones.
var syncPriority = []string{"cisa_kev", "nuclei_templates", "aliyun_avd", "github_ghsa", "nvd_cve"}

func orderDueSources(due []db.KBSource) []db.KBSource {
	rank := make(map[string]int, len(syncPriority))
	for i, key := range syncPriority {
		rank[key] = i
	}
	out := append([]db.KBSource{}, due...)
	sort.SliceStable(out, func(i, j int) bool {
		ri, iok := rank[out[i].Key]
		rj, jok := rank[out[j].Key]
		switch {
		case iok && jok:
			return ri < rj
		case iok:
			return true
		case jok:
			return false
		default:
			return false
		}
	})
	return out
}

func (s *Syncer) tick(ctx context.Context) {
	if s.DB == nil {
		return
	}
	due, err := s.DB.DueKBSources(time.Now())
	if err != nil {
		return
	}
	for _, src := range orderDueSources(due) {
		if ctx.Err() != nil {
			return
		}
		_ = s.SyncSource(ctx, src, "schedule")
	}
}

// Busy reports whether a source key is already syncing.
func (s *Syncer) Busy(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.running[key]
	return ok
}

// SyncKey loads a source by key and syncs it.
func (s *Syncer) SyncKey(ctx context.Context, key, trigger string) error {
	if s.DB == nil {
		return fmt.Errorf("知识库未初始化")
	}
	src, err := s.DB.GetKBSourceByKey(key)
	if err != nil {
		return err
	}
	if src == nil {
		return fmt.Errorf("情报源不存在")
	}
	return s.SyncSource(ctx, *src, trigger)
}

// SyncSource fetches one source. A concurrent call for the same key is skipped.
func (s *Syncer) SyncSource(ctx context.Context, src db.KBSource, trigger string) error {
	if s.DB == nil {
		return fmt.Errorf("知识库未初始化")
	}
	if !s.begin(src.Key) {
		return fmt.Errorf("同步进行中")
	}
	defer s.end(src.Key)
	runID, err := s.DB.StartKBSyncRun(src.ID, trigger)
	if err != nil {
		return err
	}
	fetched, upserted, merged := 0, 0, 0
	write := func(d Draft) error {
		row, wasMerge, err := s.DB.UpsertAndMergeKBEntry(d.Entry())
		if err != nil {
			return err
		}
		if wasMerge {
			merged++
		} else {
			upserted++
		}
		s.maybeDistill(ctx, src, row)
		return nil
	}
	hollow := 0
	writeIfSignal := func(d Draft) error {
		if d.IsHollow() {
			hollow++
			return nil
		}
		return write(d)
	}
	var gate *enrichGate
	emit := writeIfSignal
	if IsEnrichOnlySource(src) {
		gate = newEnrichGate(s.DB, writeIfSignal)
		emit = gate.offer
	}
	cursor, ferr := s.dispatch(ctx, src, func(d Draft) error {
		fetched++
		return emit(d)
	})
	if gate != nil {
		if err := gate.finish(); err != nil && ferr == nil {
			ferr = err
		}
	}
	skipped := hollow
	if gate != nil {
		skipped += gate.skipped
	}
	status := "ok"
	errText := ""
	if ferr != nil {
		status = "error"
		errText = ferr.Error()
	}
	count, cerr := s.DB.RefreshKBSourceCount(src.ID, src.Key)
	if cerr != nil {
		count = src.EntryCount
	}
	_ = s.DB.MarkKBSourceSync(src.ID, status, errText, cursor, count)
	_ = s.DB.FinishKBSyncRun(runID, status, fetched, upserted, merged, skipped, errText)
	return ferr
}

// enrichOnlyBatch bounds the number of drafts whose existence is checked at once.
// An NVD page is 100 rows; one query per batch keeps the sync cheap.
const enrichOnlyBatch = 200

// enrichGate applies enrich-only admission to a stream of drafts. Drafts arrive one
// at a time from the feed parsers, so it buffers them and resolves each batch with a
// single existence query, then hands the survivors to write.
type enrichGate struct {
	db      *db.DB
	write   func(Draft) error
	pending []Draft
	skipped int
}

func newEnrichGate(database *db.DB, write func(Draft) error) *enrichGate {
	return &enrichGate{db: database, write: write}
}

// offer buffers a draft and flushes the batch when it fills up.
func (g *enrichGate) offer(d Draft) error {
	g.pending = append(g.pending, d)
	if len(g.pending) >= enrichOnlyBatch {
		return g.flush()
	}
	return nil
}

// finish flushes whatever is left in the buffer.
func (g *enrichGate) finish() error { return g.flush() }

// flush resolves the buffered drafts in one query. Rows already local, or drafts
// that carry their own PoC or KEV flag, are written; the rest are dropped. A query
// failure admits everything rather than silently discarding intelligence.
func (g *enrichGate) flush() error {
	if len(g.pending) == 0 {
		return nil
	}
	batch := g.pending
	g.pending = nil
	var refs []string
	for _, d := range batch {
		refs = append(refs, draftRefs(d)...)
	}
	existing, err := g.db.ExistingKBRefs(refs)
	if err != nil {
		existing = nil
	}
	for _, d := range batch {
		if !DraftEntitled(d, existing) {
			g.skipped++
			continue
		}
		if err := g.write(d); err != nil {
			return err
		}
	}
	return nil
}

// DraftEntitled reports whether a draft from an enrich-only feed may reach the
// store, given the refs that already exist locally. A draft is entitled when it
// brings its own signal (a PoC, or the KEV flag) or when it has something to
// enrich — i.e. a local row shares its identity. Everything else is the bare
// advisory shell the plan calls a hollow CVE.
func DraftEntitled(d Draft, existing map[string]bool) bool {
	if strings.TrimSpace(d.PocSnippet) != "" || d.ActivelyExploited {
		return true
	}
	for _, ref := range draftRefs(d) {
		if existing[ref] {
			return true
		}
	}
	return false
}

// draftRefs are the identities a draft is allowed to land on. A KEV/Nuclei row
// created the local cve:... first; the same CVE arriving from NVD must resolve
// against it, so the nkey, the raw external id and its upper-cased form all count.
func draftRefs(d Draft) []string {
	refs := []string{db.CanonicalNKey(d.ExternalID, d.Kind, d.Title, d.NKey)}
	if ext := strings.TrimSpace(d.ExternalID); ext != "" {
		refs = append(refs, ext, strings.ToUpper(ext))
	}
	return refs
}

// IsHollow reports whether a draft carries nothing beyond a restated advisory:
// no PoC, not known-exploited, no summary of its own, and a detection guide that
// is just the feed's boilerplate. Such a draft would be deleted by the next
// PurgeHollowSyncedCVEs, so it is never written in the first place.
func (d Draft) IsHollow() bool {
	if strings.TrimSpace(d.PocSnippet) != "" || d.ActivelyExploited {
		return false
	}
	if strings.TrimSpace(d.Summary) != "" {
		return false
	}
	guide := strings.TrimSpace(d.DetectionGuide)
	if guide == "" {
		return true
	}
	for _, boilerplate := range DefaultHollowGuides() {
		if guide == boilerplate || strings.HasPrefix(guide, boilerplate) {
			return true
		}
	}
	return false
}

// enrichOnlyKeys are the feeds that only ever restate a public advisory: NVD,
// GHSA and Aliyun AVD. They enrich a row somebody else established (KEV, Nuclei,
// a distilled finding, a manual import) and never create a bare CVE by themselves.
var enrichOnlyKeys = map[string]bool{"nvd_cve": true, "github_ghsa": true, "aliyun_avd": true}

// enrichOnlyKinds is the fallback for a custom source configured on one of those
// feeds under a different key.
var enrichOnlyKinds = map[string]bool{"nvd": true, "ghsa": true, "avd": true}

// IsEnrichOnlySource reports whether a source may only enrich existing entries.
// An explicit config "enrich_only" wins over the built-in default.
func IsEnrichOnlySource(src db.KBSource) bool {
	if v, ok := configMap(src.Config)["enrich_only"]; ok {
		switch t := v.(type) {
		case bool:
			return t
		case string:
			return t == "true" || t == "1"
		}
		return false
	}
	return enrichOnlyKeys[src.Key] || enrichOnlyKinds[src.Kind]
}

func (s *Syncer) begin(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running == nil {
		s.running = map[string]struct{}{}
	}
	if _, ok := s.running[key]; ok {
		return false
	}
	s.running[key] = struct{}{}
	return true
}

func (s *Syncer) end(key string) {
	s.mu.Lock()
	delete(s.running, key)
	s.mu.Unlock()
}

func (s *Syncer) dispatch(ctx context.Context, src db.KBSource, emit func(Draft) error) (string, error) {
	c := s.client()
	switch src.Kind {
	case "cisa_kev":
		return syncKEV(ctx, c, src, emit)
	case "nuclei":
		return syncNuclei(ctx, c, src, emit)
	case "nvd":
		return syncNVD(ctx, c, src, emit)
	case "ghsa":
		return syncGHSA(ctx, c, src, emit)
	case "avd":
		return syncAVD(ctx, c, src, emit)
	case "seebug", "rss":
		return syncSeebug(ctx, c, src, emit)
	case "git_markdown":
		return syncGit(ctx, c, src, emit)
	default:
		return src.Cursor, fmt.Errorf("未知源类型 %s", src.Kind)
	}
}

func (s *Syncer) maybeDistill(ctx context.Context, src db.KBSource, row db.KBEntry) {
	if s.Distill == nil || row.ContentLocked || strings.TrimSpace(row.DetectionGuide) != "" {
		return
	}
	if !configBool(configMap(src.Config), "distill") {
		return
	}
	fields, err := s.Distill(ctx, row)
	if err != nil || strings.TrimSpace(fields.DetectionGuide) == "" {
		return
	}
	_ = s.DB.SetKBDetectionGuide(row.ID, fields.Summary, fields.DetectionGuide, fields.VulnClass, fields.Products)
}

func configBool(m map[string]any, key string) bool {
	switch v := m[key].(type) {
	case bool:
		return v
	case string:
		return v == "true" || v == "1"
	default:
		return false
	}
}

// FetchCVE pulls one CVE from NVD, GHSA and Nuclei when it is missing locally.
func (s *Syncer) FetchCVE(ctx context.Context, cveID string) error {
	if s.DB == nil {
		return fmt.Errorf("知识库未初始化")
	}
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	if upperCVE(cveID) != cveID {
		return fmt.Errorf("不是 CVE 编号")
	}
	if row, err := s.DB.GetKBEntryByExternalID(cveID); err == nil && row != nil {
		return nil
	}
	c := s.client()
	var drafts []Draft
	if src, err := s.DB.GetKBSourceByKey("nvd_cve"); err == nil && src != nil {
		if ds, err := fetchNVDByCVE(ctx, c, *src, cveID); err == nil {
			drafts = append(drafts, ds...)
		}
	}
	if src, err := s.DB.GetKBSourceByKey("github_ghsa"); err == nil && src != nil {
		if ds, err := fetchGHSAByCVE(ctx, c, *src, cveID); err == nil {
			drafts = append(drafts, ds...)
		}
	}
	if d, err := fetchNucleiCVE(ctx, c, "nuclei_templates", cveID); err == nil {
		drafts = append(drafts, d)
	}
	if len(drafts) == 0 {
		return fmt.Errorf("未从公开源拉取到 %s", cveID)
	}
	var last error
	ok := 0
	for _, d := range drafts {
		if _, _, err := s.DB.UpsertAndMergeKBEntry(d.Entry()); err != nil {
			last = err
			continue
		}
		ok++
	}
	if ok == 0 {
		return last
	}
	return nil
}
