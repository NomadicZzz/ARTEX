package server

import (
	"context"
	"strings"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/kb"
)

// KBSyncer is the process-wide knowledge sync loop.
type KBSyncer struct {
	s     *Server
	inner *kb.Syncer
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
