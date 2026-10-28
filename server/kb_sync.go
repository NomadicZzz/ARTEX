package server

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/kb"
)

// KBSyncer is the process-wide knowledge sync loop.
type KBSyncer struct {
	s        *Server
	inner    *kb.Syncer
	mu       sync.Mutex
	inflight map[int64]struct{}
}

func newKBSyncer(s *Server) *KBSyncer {
	inner := kb.NewSyncer(s.m.pg, func() string {
		if s.m == nil {
			return ""
		}
		return s.m.GlobalProxy()
	})
	inner.Distill = func(ctx context.Context, entry db.KBEntry) (kb.DistillFields, error) {
		return s.distillKBText(ctx, entry.Title, entry.Summary, entry.PocSnippet)
	}
	return &KBSyncer{s: s, inner: inner}
}

func (k *KBSyncer) Run(ctx context.Context) {
	if k == nil || k.inner == nil {
		return
	}
	k.inner.Run(ctx)
}

func (k *KBSyncer) FetchCVE(ctx context.Context, cveID string) error {
	if k == nil || k.inner == nil {
		return nil
	}
	return k.inner.FetchCVE(ctx, cveID)
}

func (k *KBSyncer) Busy(key string) bool {
	return k != nil && k.inner != nil && k.inner.Busy(key)
}

func (k *KBSyncer) SyncKey(ctx context.Context, key, trigger string) error {
	if k == nil || k.inner == nil {
		return errString("知识库同步未启动")
	}
	return k.inner.SyncKey(ctx, key, trigger)
}

// EnqueueFindingDistill distills one confirmed finding in the background.
// A finding already in flight is left to that job. A nil syncer is a no-op so
// tests that patch status without a knowledge syncer stay quiet.
func (k *KBSyncer) EnqueueFindingDistill(findingID int64) {
	if k == nil || k.s == nil || findingID <= 0 {
		return
	}
	k.mu.Lock()
	if k.inflight == nil {
		k.inflight = map[int64]struct{}{}
	}
	if _, busy := k.inflight[findingID]; busy {
		k.mu.Unlock()
		return
	}
	k.inflight[findingID] = struct{}{}
	k.mu.Unlock()
	go func() {
		defer func() {
			k.mu.Lock()
			delete(k.inflight, findingID)
			k.mu.Unlock()
		}()
		parent := k.s.ctx
		if parent == nil {
			parent = context.Background()
		}
		ctx, cancel := context.WithTimeout(parent, 3*time.Minute)
		defer cancel()
		if _, _, err := k.s.DistillAndSaveFinding(ctx, findingID, "auto", 0, "", nil); err != nil {
			log.Printf("[kb] 自动沉淀 finding=%d: %v", findingID, err)
		}
	}()
}

type errString string

func (e errString) Error() string { return string(e) }

func (s *Server) distillKBText(ctx context.Context, title, summary, poc string) (kb.DistillFields, error) {
	s.cfgMu.Lock()
	prov := s.llmProv
	on := s.llmOn
	s.cfgMu.Unlock()
	if !on || prov == nil {
		return kb.DistillFields{}, errString("LLM 未配置")
	}
	user := "标题: " + title + "\n摘要: " + kb.RedactSensitive(summary) + "\n材料: " + kb.RedactSensitive(clipRunes(poc, 6000))
	text, err := streamCollectText(ctx, prov, kb.DistillSystem, user)
	if err != nil {
		return kb.DistillFields{}, err
	}
	return kb.ParseDistillJSON(text)
}

func clipRunes(s string, n int) string {
	s = strings.TrimSpace(s)
	rs := []rune(s)
	if n <= 0 || len(rs) <= n {
		return s
	}
	return string(rs[:n])
}
