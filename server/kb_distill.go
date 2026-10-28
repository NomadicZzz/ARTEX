package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/kb"
)

const settingKBAutoDistill = "kb_auto_distill_on_confirm"

type distillError struct {
	code int
	msg  string
}

func (e *distillError) Error() string { return e.msg }

type findingDistillRequest struct {
	ExtraNotes string            `json:"extra_notes"`
	TargetKBID int64             `json:"target_kb_id"`
	Mode       string            `json:"mode"`
	Draft      *kb.DistillFields `json:"draft"`
}

func (s *Server) previewFindingDistill(w http.ResponseWriter, r *http.Request) {
	id, ok := kbPathID(w, r)
	if !ok {
		return
	}
	req, err := readDistillRequest(r)
	if err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	prepared, err := s.prepareFindingDistill(id, req.ExtraNotes, req.TargetKBID)
	if err != nil {
		writeDistillErr(w, err)
		return
	}
	fields := kb.DistillFinding(r.Context(), prepared.Input, s.completeDistill)
	targetID := int64(0)
	if prepared.Input.ExistingKB != nil {
		targetID = prepared.Input.ExistingKB.ID
	}
	writeJSON(w, 200, map[string]any{
		"finding_id":             id,
		"suggested_mode":         fields.SuggestedMode,
		"target_kb_id":           targetID,
		"linked_kb_entries":      findingKBDTOs(prepared.Linked),
		"draft":                  fields,
		"redacted_traffic_count": prepared.TrafficCount,
	})
}

// distillFindingKB saves an edited draft when mode and draft are both present.
// An empty body keeps the old one-click behavior: preview, then save the suggested mode.
func (s *Server) distillFindingKB(w http.ResponseWriter, r *http.Request) {
	id, ok := kbPathID(w, r)
	if !ok {
		return
	}
	req, err := readDistillRequest(r)
	if err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	mode := strings.TrimSpace(req.Mode)
	draft := req.Draft
	if (draft == nil) != (mode == "") {
		writeErr(w, 400, "确认入库需要同时提供 mode 和 draft")
		return
	}
	if mode == "" {
		mode = "auto"
	}
	row, savedMode, err := s.DistillAndSaveFinding(r.Context(), id, mode, req.TargetKBID, req.ExtraNotes, draft)
	if err != nil {
		writeDistillErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"entry": row, "finding_id": id, "mode": savedMode, "kb_entry_id": row.ID})
}

func (s *Server) batchDistillFindingsKB(w http.ResponseWriter, r *http.Request) {
	if s.m == nil || s.m.pg == nil {
		writeErr(w, 503, "知识库未启用")
		return
	}
	var body struct {
		FindingIDs []int64 `json:"finding_ids"`
		Mode       string  `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if len(body.FindingIDs) == 0 {
		writeErr(w, 400, "finding_ids 为空")
		return
	}
	if len(body.FindingIDs) > 10 {
		writeErr(w, 400, "一次最多沉淀 10 条")
		return
	}
	mode := strings.TrimSpace(body.Mode)
	if mode == "" {
		mode = "auto"
	}
	okRows := make([]map[string]any, 0)
	skipped := make([]map[string]any, 0)
	failed := make([]map[string]any, 0)
	for _, id := range body.FindingIDs {
		row, savedMode, err := s.DistillAndSaveFinding(r.Context(), id, mode, 0, "", nil)
		if err != nil {
			code, msg := distillStatus(err)
			if code == 404 || strings.Contains(msg, "误报") {
				skipped = append(skipped, map[string]any{"finding_id": id, "reason": msg})
			} else {
				failed = append(failed, map[string]any{"finding_id": id, "error": msg})
			}
			continue
		}
		okRows = append(okRows, map[string]any{"finding_id": id, "kb_entry_id": row.ID, "mode": savedMode})
	}
	writeJSON(w, 200, map[string]any{"ok": okRows, "skipped": skipped, "errors": failed})
}

type preparedDistill struct {
	Input        kb.FindingDistillInput
	Linked       []db.KBEntry
	TrafficCount int
}

// DistillAndSaveFinding redacts one finding and writes the draft.
// mode auto uses the model's suggested mode. A non-nil draft is saved as edited
// and is redacted again; the model is not asked to replace it.
func (s *Server) DistillAndSaveFinding(ctx context.Context, findingID int64, mode string, targetID int64, extra string, draft *kb.DistillFields) (db.KBEntry, string, error) {
	if s.m == nil || s.m.pg == nil {
		return db.KBEntry{}, "", &distillError{code: 503, msg: "知识库未启用"}
	}
	prepared, err := s.prepareFindingDistill(findingID, extra, targetID)
	if err != nil {
		return db.KBEntry{}, "", err
	}
	fields := kb.DistillFinding(ctx, prepared.Input, s.completeDistill)
	if draft != nil {
		fields = redactDistillFields(*draft)
	}
	saveMode := strings.TrimSpace(mode)
	if saveMode == "" || saveMode == "auto" {
		saveMode = fields.SuggestedMode
	}
	if saveMode != "enrich_existing" {
		saveMode = "new_entry"
	}
	target := targetID
	if saveMode == "enrich_existing" {
		if target <= 0 && prepared.Input.ExistingKB != nil {
			target = prepared.Input.ExistingKB.ID
		}
		if target <= 0 {
			return db.KBEntry{}, "", &distillError{code: 400, msg: "未指定要补充的知识条目"}
		}
	}
	row, err := s.m.pg.SaveDistilledFindingKB(db.DistillSave{
		FindingID: findingID, Mode: saveMode, TargetKBID: target, Draft: distillFieldsToEntry(fields),
	})
	if err != nil {
		return db.KBEntry{}, "", err
	}
	return row, saveMode, nil
}

func (s *Server) prepareFindingDistill(findingID int64, extra string, targetID int64) (preparedDistill, error) {
	if s.m == nil || s.m.pg == nil {
		return preparedDistill{}, &distillError{code: 503, msg: "知识库未启用"}
	}
	src, err := s.m.pg.GetFindingDistillSource(findingID)
	if err != nil {
		return preparedDistill{}, err
	}
	if src == nil || src.Finding == nil {
		return preparedDistill{}, &distillError{code: 404, msg: "漏洞不存在"}
	}
	if src.Finding.Status == db.FindingFalsePositive {
		return preparedDistill{}, &distillError{code: 400, msg: "误报不沉淀到知识库"}
	}
	target, err := s.resolveDistillTarget(src.Linked, targetID)
	if err != nil {
		return preparedDistill{}, err
	}
	samples := s.redactedTraffic(src.Traffic)
	f := src.Finding
	in := kb.FindingDistillInput{
		FindingID: findingID, Name: f.Name, VulnClass: f.VulnClass, Severity: f.Severity,
		Summary: kb.RedactSensitive(f.Summary), Evidence: kb.RedactSensitive(f.Evidence),
		Report: kb.RedactSensitive(clipRunes(f.Report, 6000)), AssetProducts: src.Products,
		TrafficSamples: samples, ExtraNotes: kb.RedactSensitive(extra),
	}
	if target != nil {
		in.ExistingKB = &kb.DistillTarget{ID: target.ID, NKey: target.NKey, Title: target.Title, Kind: target.Kind}
	}
	count := 0
	for _, sample := range samples {
		if strings.TrimSpace(sample.RequestRaw) != "" {
			count++
		}
	}
	return preparedDistill{Input: in, Linked: src.Linked, TrafficCount: count}, nil
}

func (s *Server) resolveDistillTarget(linked []db.KBEntry, targetID int64) (*db.KBEntry, error) {
	if targetID > 0 {
		for i := range linked {
			if linked[i].ID == targetID {
				row := linked[i]
				return &row, nil
			}
		}
		row, err := s.m.pg.GetKBEntry(targetID)
		if err != nil {
			return nil, err
		}
		if row == nil {
			return nil, &distillError{code: 404, msg: "知识条目不存在"}
		}
		return row, nil
	}
	if len(linked) == 0 {
		return nil, nil
	}
	row := linked[0]
	return &row, nil
}

func (s *Server) redactedTraffic(samples []db.DistillTrafficSample) []kb.TrafficSample {
	out := make([]kb.TrafficSample, 0, len(samples))
	for _, sample := range samples {
		req := s.attachBody(sample.ReqHead, sample.ReqHash, sample.ReqLen, "request")
		resp := s.attachBody(sample.RespHead, sample.RespHash, sample.RespLen, "response")
		req, resp = kb.RedactHTTPPacket(req, resp)
		out = append(out, kb.TrafficSample{
			Method: sample.Method, URL: kb.RedactSensitive(sample.URL),
			RequestRaw: req, ResponseStatus: sample.Status, ResponseRaw: resp,
		})
	}
	return out
}

func (s *Server) attachBody(head, hash string, length int64, side string) string {
	head = strings.TrimSpace(head)
	if hash == "" || length <= 0 || s == nil || s.m == nil {
		return head
	}
	snap := db.TrafficEvidenceSnapshot{}
	if side == "response" {
		snap.RespHash, snap.RespLen = hash, length
	} else {
		snap.ReqHash, snap.ReqLen = hash, length
	}
	preview, err := readEvidencePreview(s.evidenceStore(), snap, side, 0, 4096)
	if err != nil || preview.Binary || strings.TrimSpace(preview.Content) == "" {
		return head
	}
	return joinHTTPHead(head, preview.Content)
}

func joinHTTPHead(head, body string) string {
	head = strings.TrimRight(head, "\r\n")
	body = strings.TrimSpace(body)
	if head == "" {
		return body
	}
	if body == "" {
		return head
	}
	return head + "\n\n" + body
}

func (s *Server) completeDistill(ctx context.Context, system, user string) (string, error) {
	s.cfgMu.Lock()
	prov := s.llmProv
	on := s.llmOn
	s.cfgMu.Unlock()
	if !on || prov == nil {
		return "", errString("LLM 未配置")
	}
	return streamCollectText(ctx, prov, system, user)
}

func (s *Server) distillFindingToKB(ctx context.Context, findingID int64, mode string, targetKBID int64, extraNotes string) (int64, string, error) {
	if mode == "" {
		mode = "auto"
	}
	row, _, err := s.DistillAndSaveFinding(ctx, findingID, mode, targetKBID, extraNotes, nil)
	if err != nil {
		return 0, "", err
	}
	return row.ID, row.NKey, nil
}

func (s *Server) autoDistillEnabled(explicit *bool) bool {
	if explicit != nil {
		return *explicit
	}
	if s.m == nil || s.m.pg == nil {
		return true
	}
	v, ok, err := s.m.pg.GetSetting(settingKBAutoDistill)
	if err != nil || !ok {
		return true
	}
	return strings.TrimSpace(strings.ToLower(v)) != "false"
}

func redactDistillFields(in kb.DistillFields) kb.DistillFields {
	in.Summary = kb.RedactSensitive(in.Summary)
	in.DetectionGuide = kb.RedactSensitive(in.DetectionGuide)
	in.PocSnippet = kb.RedactSensitive(in.PocSnippet)
	in.Remediation = kb.RedactSensitive(in.Remediation)
	return in
}

func distillFieldsToEntry(f kb.DistillFields) db.KBEntry {
	kind := strings.TrimSpace(f.Kind)
	if kind != "poc" && kind != "methodology" && kind != "checklist" {
		kind = "methodology"
	}
	sev := strings.ToLower(strings.TrimSpace(f.Severity))
	if !db.ValidKBSeverity(sev) {
		sev = db.KBSevInfo
	}
	return db.KBEntry{
		Title: f.Title, Summary: f.Summary, DetectionGuide: f.DetectionGuide,
		PocSnippet: f.PocSnippet, Remediation: f.Remediation,
		Kind: kind, Severity: sev, VulnClass: f.VulnClass,
		Products: f.Products, Tags: f.Tags,
	}
}

func findingKBDTOs(rows []db.KBEntry) []FindingKBDTO {
	out := make([]FindingKBDTO, 0, len(rows))
	for _, e := range rows {
		out = append(out, FindingKBDTO{
			ID: e.ID, ExternalID: e.ExternalID, Title: e.Title, Severity: e.Severity,
			Kind: e.Kind, HasPoC: e.HasPoC, FromDistill: kbFromDistill(e),
		})
	}
	return out
}

func kbFromDistill(e db.KBEntry) bool {
	if e.Origin == "finding_distilled" {
		return true
	}
	for _, key := range e.SourceKeys {
		if key == "finding_distilled" {
			return true
		}
	}
	return false
}

func readDistillRequest(r *http.Request) (findingDistillRequest, error) {
	var req findingDistillRequest
	if r.Body == nil {
		return req, nil
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return req, err
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return req, nil
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return req, err
	}
	return req, nil
}

func writeDistillErr(w http.ResponseWriter, err error) {
	code, msg := distillStatus(err)
	writeErr(w, code, msg)
}

func distillStatus(err error) (int, string) {
	var de *distillError
	if errors.As(err, &de) {
		return de.code, de.msg
	}
	return 400, err.Error()
}
