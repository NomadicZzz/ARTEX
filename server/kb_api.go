package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/kb"
)

var builtinKBKeys = map[string]bool{
	"cisa_kev": true, "nuclei_templates": true, "nvd_cve": true, "github_ghsa": true,
	"aliyun_avd": true, "seebug_rss": true, "custom_git_kb": true,
}

func (s *Server) kbDB(w http.ResponseWriter) *db.DB {
	if s.m == nil || s.m.PG() == nil {
		writeErr(w, 503, "知识库未启用")
		return nil
	}
	return s.m.PG()
}

func kbPathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "id 无效")
		return 0, false
	}
	return id, true
}

func (s *Server) kbStats(w http.ResponseWriter, r *http.Request) {
	pg := s.kbDB(w)
	if pg == nil {
		return
	}
	total, kev, method, poc, err := pg.KBEntryCounts()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	st := db.KBStats{Total: total, KEV: kev, Methodology: method, WithPoC: poc}
	if idx, err := pg.AssetFingerprintIndex(); err == nil {
		if rows, err := pg.ListKBProductIndex(); err == nil {
			st.MatchedEntries, st.MatchedAssets = db.CountAssetHits(rows, idx)
		}
	}
	writeJSON(w, 200, st)
}

func (s *Server) kbSearch(w http.ResponseWriter, r *http.Request) {
	pg := s.kbDB(w)
	if pg == nil {
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	query := db.KBQuery{
		Q: q.Get("q"), VulnClass: q.Get("vulnclass"), MinSeverity: q.Get("min_severity"),
		Kind: q.Get("kind"), Limit: limit, Offset: offset,
	}
	if p := strings.TrimSpace(q.Get("products")); p != "" {
		query.Products = splitCSV(p)
	}
	if b, ok := queryBool(q.Get("actively_exploited")); ok {
		query.ActivelyExploited = &b
	}
	if b, ok := queryBool(q.Get("has_poc")); ok {
		query.HasPoC = &b
	}
	var idx map[string][]int64
	if q.Get("matched_assets_only") == "1" || q.Get("matched_assets_only") == "true" {
		var err error
		idx, err = pg.AssetFingerprintIndex()
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		query.MatchedProducts = db.FingerprintSet(idx)
	}
	entries, total, err := pg.SearchKBEntries(query)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if idx == nil {
		idx, _ = pg.AssetFingerprintIndex()
	}
	for i := range entries {
		if idx != nil {
			entries[i].MatchedAssetCount = db.CountMatchedAssets(entries[i].Products, idx)
		}
		entries[i].DetectionGuide = ""
		entries[i].PocSnippet = ""
		entries[i].Remediation = ""
	}
	writeJSON(w, 200, map[string]any{"items": entries, "total": total})
}

func (s *Server) kbGetEntry(w http.ResponseWriter, r *http.Request) {
	pg := s.kbDB(w)
	if pg == nil {
		return
	}
	id, ok := kbPathID(w, r)
	if !ok {
		return
	}
	e, err := pg.GetKBEntry(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if e == nil {
		writeErr(w, 404, "条目不存在")
		return
	}
	var matched []db.KBAssetHit
	if idx, err := pg.AssetFingerprintIndex(); err == nil {
		e.MatchedAssetCount = db.CountMatchedAssets(e.Products, idx)
		matched, _ = pg.MatchedAssetsForEntry(e.Products, idx, 50)
	}
	related, _ := pg.RelatedFindingsForKB(id, 20)
	writeJSON(w, 200, map[string]any{"entry": e, "matched_assets": matched, "related_findings": related})
}

func (s *Server) kbCreateEntry(w http.ResponseWriter, r *http.Request) {
	pg := s.kbDB(w)
	if pg == nil {
		return
	}
	var in db.KBEntry
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		writeErr(w, 400, "请求体不是 JSON")
		return
	}
	if in.Origin == "" {
		in.Origin = "manual"
	}
	in.Enabled = true
	row, _, err := pg.UpsertAndMergeKBEntry(in)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, row)
}

func (s *Server) kbUpdateEntry(w http.ResponseWriter, r *http.Request) {
	pg := s.kbDB(w)
	if pg == nil {
		return
	}
	id, ok := kbPathID(w, r)
	if !ok {
		return
	}
	var in db.KBEntry
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		writeErr(w, 400, "请求体不是 JSON")
		return
	}
	row, err := pg.UpdateKBEntryContent(id, in)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, row)
}

func (s *Server) kbDeleteEntry(w http.ResponseWriter, r *http.Request) {
	pg := s.kbDB(w)
	if pg == nil {
		return
	}
	id, ok := kbPathID(w, r)
	if !ok {
		return
	}
	if err := pg.DeleteKBEntry(id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) kbDistillEntry(w http.ResponseWriter, r *http.Request) {
	pg := s.kbDB(w)
	if pg == nil {
		return
	}
	id, ok := kbPathID(w, r)
	if !ok {
		return
	}
	e, err := pg.GetKBEntry(id)
	if err != nil || e == nil {
		writeErr(w, 404, "条目不存在")
		return
	}
	fields, err := s.distillKBText(r.Context(), e.Title, e.Summary, e.PocSnippet+"\n"+e.DetectionGuide)
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	if err := pg.ApplyKBDistill(id, fields.Summary, fields.DetectionGuide, fields.VulnClass, fields.Products); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	got, _ := pg.GetKBEntry(id)
	writeJSON(w, 200, got)
}

func (s *Server) kbCreateVerifyTask(w http.ResponseWriter, r *http.Request) {
	pg := s.kbDB(w)
	if pg == nil {
		return
	}
	id, ok := kbPathID(w, r)
	if !ok {
		return
	}
	e, err := pg.GetKBEntry(id)
	if err != nil || e == nil {
		writeErr(w, 404, "条目不存在")
		return
	}
	var body struct {
		AssetIDs []int64 `json:"asset_ids"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeErr(w, 400, "请求体不是 JSON")
		return
	}
	if len(body.AssetIDs) == 0 {
		writeErr(w, 400, "至少选择一个资产")
		return
	}
	if len(body.AssetIDs) > 100 {
		body.AssetIDs = body.AssetIDs[:100]
	}
	name := clipRunes("验证 "+e.Title, 80)
	desc := fmt.Sprintf("验证知识库条目：%s\n编号：%s\n严重等级：%s\n受影响版本：%s\n产品：%s\n\n检测思路：\n%s\n\n命中只是检测线索。必须真实触发并取得证据后才能 report_finding。本任务已暂停，确认后再开始，系统不会自动发包。",
		e.Title, e.ExternalID, e.Severity, e.AffectedVersions, strings.Join(e.Products, ", "), clipRunes(e.DetectionGuide, 4000))
	task, err := s.m.CreateTaskWithOptions(desc, "在选定资产上验证该知识库条目。命中只是线索，必须真实触发并取得证据后才能 report_finding。", db.TaskCreateOptions{Name: name})
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if err := s.m.ApplyTaskPause(task.ID); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if s.engine != nil {
		s.engine.Pause(task.ID, agent.Causef("kb_verify_paused", "等待人工确认", "知识库验证任务已创建，需在任务页手动开始"))
	}
	taskID, _ := strconv.ParseInt(task.ID, 10, 64)
	if as := s.assetStore(); as != nil && taskID > 0 {
		_, _ = as.AttachAssetsToTask(taskID, body.AssetIDs, "知识库验证任务")
		if assets, err := as.GetByIDs(body.AssetIDs); err == nil {
			for _, a := range assets {
				_ = as.AddAutoScope(taskID, a.Type, a.Domain, a.URL, a.IP)
			}
		}
	}
	writeJSON(w, 200, map[string]any{
		"task_id": task.ID,
		"paused":  true,
		"message": "验证任务已创建并暂停。请到任务页确认后手动开始，系统不会自动发包。",
	})
}

func (s *Server) kbImport(w http.ResponseWriter, r *http.Request) {
	pg := s.kbDB(w)
	if pg == nil {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
	if err != nil || len(body) > 1<<20 {
		writeErr(w, 400, "导入内容超过 1MB")
		return
	}
	var wrap struct {
		Format  string          `json:"format"`
		Content string          `json:"content"`
		Entries []db.KBEntry    `json:"entries"`
		Raw     json.RawMessage `json:"-"`
	}
	_ = json.Unmarshal(body, &wrap)
	var entries []db.KBEntry
	switch {
	case len(wrap.Entries) > 0:
		entries = wrap.Entries
	case strings.TrimSpace(wrap.Content) != "" && (wrap.Format == "markdown" || wrap.Format == "md" || !strings.HasPrefix(strings.TrimSpace(wrap.Content), "{") && !strings.HasPrefix(strings.TrimSpace(wrap.Content), "[")):
		entries = markdownKBEntries(wrap.Content)
	default:
		payload := body
		if strings.TrimSpace(wrap.Content) != "" {
			payload = []byte(wrap.Content)
		}
		var list []db.KBEntry
		if json.Unmarshal(payload, &list) == nil && len(list) > 0 {
			entries = list
		} else {
			var one db.KBEntry
			if json.Unmarshal(payload, &one) == nil && (one.Title != "" || one.ExternalID != "") {
				entries = []db.KBEntry{one}
			}
		}
	}
	if len(entries) == 0 {
		writeErr(w, 400, "没有可导入的条目")
		return
	}
	if len(entries) > 50 {
		entries = entries[:50]
	}
	var ids []int64
	for _, e := range entries {
		if e.Origin == "" {
			e.Origin = "manual"
		}
		if e.Kind == "" {
			e.Kind = "methodology"
		}
		e.Enabled = true
		row, _, err := pg.UpsertAndMergeKBEntry(e)
		if err != nil {
			continue
		}
		ids = append(ids, row.ID)
	}
	writeJSON(w, 200, map[string]any{"imported": len(ids), "ids": ids})
}

func markdownKBEntries(content string) []db.KBEntry {
	lines := strings.Split(content, "\n")
	var chunks [][]string
	var cur []string
	for _, line := range lines {
		if strings.HasPrefix(line, "# ") && len(cur) > 0 {
			chunks = append(chunks, cur)
			cur = nil
		}
		cur = append(cur, line)
	}
	if len(cur) > 0 {
		chunks = append(chunks, cur)
	}
	var out []db.KBEntry
	for _, chunk := range chunks {
		text := strings.TrimSpace(strings.Join(chunk, "\n"))
		if text == "" {
			continue
		}
		title := ""
		body := text
		if strings.HasPrefix(text, "# ") {
			parts := strings.SplitN(text, "\n", 2)
			title = strings.TrimSpace(strings.TrimPrefix(parts[0], "# "))
			if len(parts) == 2 {
				body = parts[1]
			} else {
				body = ""
			}
		}
		if title == "" {
			title = clipRunes(strings.TrimSpace(text), 80)
		}
		out = append(out, db.KBEntry{
			Title: title, DetectionGuide: strings.TrimSpace(body), Summary: clipRunes(strings.TrimSpace(body), 400),
			Kind: "methodology", Origin: "manual", Severity: "info",
		})
	}
	return out
}

func (s *Server) kbListSources(w http.ResponseWriter, r *http.Request) {
	pg := s.kbDB(w)
	if pg == nil {
		return
	}
	rows, err := pg.ListKBSources()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, src := range rows {
		out = append(out, publicKBSource(src))
	}
	writeJSON(w, 200, map[string]any{"sources": out})
}

func (s *Server) kbCreateSource(w http.ResponseWriter, r *http.Request) {
	pg := s.kbDB(w)
	if pg == nil {
		return
	}
	var in kbSourceInput
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		writeErr(w, 400, "请求体不是 JSON")
		return
	}
	in.Key = strings.TrimSpace(in.Key)
	in.Kind = strings.TrimSpace(in.Kind)
	if !validSourceKey(in.Key) || !validSourceKind(in.Kind) {
		writeErr(w, 400, "key 或 kind 不合法")
		return
	}
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	row, err := pg.CreateKBSource(db.KBSource{
		Key: in.Key, Name: in.Name, Kind: in.Kind, Enabled: enabled,
		SyncIntervalSec: in.SyncIntervalSec, Config: in.Config,
	})
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, publicKBSource(*row))
}

func (s *Server) kbUpdateSource(w http.ResponseWriter, r *http.Request) {
	pg := s.kbDB(w)
	if pg == nil {
		return
	}
	id, ok := kbPathID(w, r)
	if !ok {
		return
	}
	cur, err := pg.GetKBSource(id)
	if err != nil || cur == nil {
		writeErr(w, 404, "情报源不存在")
		return
	}
	var in kbSourceInput
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		writeErr(w, 400, "请求体不是 JSON")
		return
	}
	enabled := cur.Enabled
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	cfg := mergeSourceConfig(cur.Config, in.Config)
	row, err := pg.UpdateKBSource(id, db.KBSource{
		Name: in.Name, Enabled: enabled, SyncIntervalSec: in.SyncIntervalSec, Config: cfg,
	})
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, publicKBSource(*row))
}

func (s *Server) kbDeleteSource(w http.ResponseWriter, r *http.Request) {
	pg := s.kbDB(w)
	if pg == nil {
		return
	}
	id, ok := kbPathID(w, r)
	if !ok {
		return
	}
	if err := pg.DeleteKBSource(id); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) kbSyncSource(w http.ResponseWriter, r *http.Request) {
	pg := s.kbDB(w)
	if pg == nil {
		return
	}
	id, ok := kbPathID(w, r)
	if !ok {
		return
	}
	src, err := pg.GetKBSource(id)
	if err != nil || src == nil {
		writeErr(w, 404, "情报源不存在")
		return
	}
	if s.kbSync == nil {
		writeErr(w, 503, "同步未启动")
		return
	}
	if s.kbSync.Busy(src.Key) {
		writeJSON(w, 200, map[string]any{"status": "running"})
		return
	}
	go func(key string) {
		ctx, cancel := context.WithTimeout(s.ctx, 2*time.Hour)
		defer cancel()
		_ = s.kbSync.SyncKey(ctx, key, "manual")
	}(src.Key)
	writeJSON(w, 202, map[string]any{"status": "started"})
}

func (s *Server) kbListSyncRuns(w http.ResponseWriter, r *http.Request) {
	pg := s.kbDB(w)
	if pg == nil {
		return
	}
	sourceID, _ := strconv.ParseInt(r.URL.Query().Get("source_id"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	rows, err := pg.ListKBSyncRuns(sourceID, limit)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"runs": rows})
}

func (s *Server) distillFindingKB(w http.ResponseWriter, r *http.Request) {
	pg := s.kbDB(w)
	if pg == nil {
		return
	}
	id, ok := kbPathID(w, r)
	if !ok {
		return
	}
	f, err := pg.GetFinding(id)
	if err != nil || f == nil {
		writeErr(w, 404, "漏洞不存在")
		return
	}
	title := f.Name
	if title == "" {
		title = f.VulnClass
	}
	if title == "" {
		title = fmt.Sprintf("漏洞 #%d", id)
	}
	summary := kb.RedactSensitive(f.Summary)
	guide := "来自已登记漏洞的沉淀。下面是脱敏后的证据，只作为后续检测线索，不能代替在新目标上的再次触发。\n\n" + clipRunes(kb.RedactSensitive(f.Evidence), 4000)
	products := []string{}
	vulnclass := f.VulnClass
	if fields, err := s.distillKBText(r.Context(), title, summary+"\n"+kb.RedactSensitive(f.Report), guide); err == nil {
		if fields.Summary != "" {
			summary = fields.Summary
		}
		if fields.DetectionGuide != "" {
			guide = fields.DetectionGuide
		}
		if len(fields.Products) > 0 {
			products = fields.Products
		}
		if fields.VulnClass != "" {
			vulnclass = fields.VulnClass
		}
	}
	entry := db.KBEntry{
		NKey: fmt.Sprintf("finding:%d", id), Title: title, Summary: summary, DetectionGuide: guide,
		Kind: "methodology", Origin: "finding_distilled", Severity: f.Severity, VulnClass: vulnclass,
		Products: products, SourceKeys: []string{"finding_distilled"}, Enabled: true,
	}
	row, _, err := pg.UpsertAndMergeKBEntry(entry)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if refreshed, err := pg.UpdateKBEntryContent(row.ID, entry); err == nil {
		row = refreshed
	}
	_ = pg.AddFindingKBEntry(id, row.ID)
	writeJSON(w, 200, map[string]any{"entry": row, "finding_id": id})
}

type kbSourceInput struct {
	Key             string          `json:"key"`
	Name            string          `json:"name"`
	Kind            string          `json:"kind"`
	Enabled         *bool           `json:"enabled"`
	SyncIntervalSec int             `json:"sync_interval_sec"`
	Config          json.RawMessage `json:"config"`
}

func publicKBSource(s db.KBSource) map[string]any {
	cfg := map[string]any{}
	_ = json.Unmarshal(s.Config, &cfg)
	set := false
	if key, _ := cfg["api_key"].(string); strings.TrimSpace(key) != "" {
		set = true
	}
	delete(cfg, "api_key")
	raw, _ := json.Marshal(cfg)
	if len(raw) == 0 || string(raw) == "null" {
		raw = []byte(`{}`)
	}
	return map[string]any{
		"id": s.ID, "key": s.Key, "name": s.Name, "kind": s.Kind, "enabled": s.Enabled,
		"sync_interval_sec": s.SyncIntervalSec, "config": json.RawMessage(raw), "api_key_set": set,
		"cursor": s.Cursor, "last_sync_at": s.LastSyncAt, "last_status": s.LastStatus,
		"last_error": s.LastError, "entry_count": s.EntryCount, "builtin": builtinKBKeys[s.Key],
	}
}

func mergeSourceConfig(old, incoming json.RawMessage) json.RawMessage {
	if len(incoming) == 0 {
		return old
	}
	var prev, next map[string]any
	_ = json.Unmarshal(old, &prev)
	if json.Unmarshal(incoming, &next) != nil || next == nil {
		return old
	}
	key, has := next["api_key"].(string)
	if !has || strings.TrimSpace(key) == "" {
		delete(next, "api_key")
		if prev != nil {
			if kept, ok := prev["api_key"]; ok {
				next["api_key"] = kept
			}
		}
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return old
	}
	return raw
}

func validSourceKind(kind string) bool {
	switch kind {
	case "cisa_kev", "nuclei", "nvd", "ghsa", "avd", "seebug", "git_markdown", "rss":
		return true
	default:
		return false
	}
}

func validSourceKey(key string) bool {
	if len(key) < 2 || len(key) > 40 {
		return false
	}
	for _, r := range key {
		if r != '_' && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func queryBool(s string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes":
		return true, true
	case "0", "false", "no":
		return false, true
	default:
		return false, false
	}
}
