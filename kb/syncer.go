package kb

import (
	"context"
	"fmt"
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

// Run ticks until ctx is cancelled.
func (s *Syncer) Run(ctx context.Context) {
	interval := s.Interval
	if interval <= 0 {
		interval = time.Minute
	}
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

func (s *Syncer) tick(ctx context.Context) {
	if s.DB == nil {
		return
	}
	due, err := s.DB.DueKBSources(time.Now())
	if err != nil {
		return
	}
	for _, src := range due {
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
	cursor, ferr := s.dispatch(ctx, src, func(d Draft) error {
		fetched++
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
	})
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
	_ = s.DB.FinishKBSyncRun(runID, status, fetched, upserted, merged, errText)
	return ferr
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
