package agent

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// KBOnDemand fetches a missing CVE into the knowledge base. The server wires it
// so this package does not import the sync engine.
var KBOnDemand func(ctx context.Context, cveID string) error

// DistillFindingToKB redacts a finding into the knowledge base. The server wires
// the LLM and the write path. mode is auto, enrich_existing, or new_entry.
// The callback returns the saved entry id and its nkey.
var DistillFindingToKB func(ctx context.Context, findingID int64, mode string, targetKBID int64, extraNotes string) (int64, string, error)

var kbCVEPattern = regexp.MustCompile(`(?i)^CVE-\d{4}-\d{4,}$`)

const kbClueNote = "知识库命中只是检测线索。必须在授权目标上真实触发并拿到证据后才能 report_finding，上报时可传 kb_entry_ids。"

const kbDetailIDCap = 5

const kbDetailLimitNote = "单次最多返回 5 条详情，剩余 ID 请分批调用"

func (t *ToolSet) searchKnowledge() actool.CoreTool {
	return readTool("search_knowledge",
		"检索知识库：公开漏洞（CVE/KEV/GHSA/AVD/Nuclei）和检测方法/检查清单。"+kbClueNote,
		obj(map[string]any{
			"q":                  str("关键词、CVE 编号或产品名"),
			"products":           map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "产品指纹，命中其一即可"},
			"vulnclass":          str("漏洞类别，精确匹配"),
			"min_severity":       str("info|low|medium|high|critical"),
			"kind":               str("cve|poc|methodology|checklist"),
			"actively_exploited": map[string]any{"type": "boolean", "description": "只看在野利用"},
			"has_poc":            map[string]any{"type": "boolean", "description": "只看带 PoC 片段的条目"},
			"limit":              intp("默认 10，最大 30"),
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if t.pg == nil {
				return actool.Errorf("知识库未启用"), nil
			}
			var a struct {
				Q                 string   `json:"q"`
				Products          []string `json:"products"`
				VulnClass         string   `json:"vulnclass"`
				MinSeverity       string   `json:"min_severity"`
				Kind              string   `json:"kind"`
				ActivelyExploited *bool    `json:"actively_exploited"`
				HasPoC            *bool    `json:"has_poc"`
				Limit             int      `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			limit := a.Limit
			if limit <= 0 {
				limit = 10
			}
			if limit > 30 {
				limit = 30
			}
			q := db.KBQuery{
				Q: a.Q, Products: a.Products, VulnClass: a.VulnClass, MinSeverity: a.MinSeverity,
				Kind: a.Kind, ActivelyExploited: a.ActivelyExploited, HasPoC: a.HasPoC, Limit: limit,
			}
			entries, total, err := t.pg.SearchKBEntries(q)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if total == 0 && kbCVEPattern.MatchString(strings.TrimSpace(a.Q)) && KBOnDemand != nil {
				_ = KBOnDemand(ctx, strings.ToUpper(strings.TrimSpace(a.Q)))
				entries, total, err = t.pg.SearchKBEntries(q)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
			}
			return jsonResult(map[string]any{
				"total":   total,
				"entries": kbListBriefs(entries),
				"note":    kbClueNote,
			})
		})
}

func (t *ToolSet) getKnowledgeDetail() actool.CoreTool {
	return readTool("get_knowledge_detail",
		"读取知识库条目全文（检测思路与 PoC 片段）。按 id 最多 5 条，external_id 另计。"+kbClueNote,
		obj(map[string]any{
			"ids":         map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "条目 id。按 id 最多 5 个，其余在 omitted_ids 里，external_id 另计"},
			"id":          idp("单个条目 id"),
			"external_id": str("CVE/GHSA/AVD 编号。库里没有的 CVE 会尝试按需拉取。不占 id 的 5 条名额"),
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if t.pg == nil {
				return actool.Errorf("知识库未启用"), nil
			}
			var a struct {
				IDs        []json.RawMessage `json:"ids"`
				ID         json.RawMessage   `json:"id"`
				ExternalID string            `json:"external_id"`
			}
			_ = json.Unmarshal(in, &a)
			ids := pidList(a.IDs)
			if v := pid(a.ID); v > 0 {
				ids = append(ids, v)
			}
			ids, omitted := splitKBDetailIDs(ids)
			var entries []db.KBEntry
			if len(ids) > 0 {
				rows, err := t.pg.ListKBEntriesByIDs(ids)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				entries = rows
			}
			ext := strings.TrimSpace(a.ExternalID)
			if ext != "" {
				row, err := t.lookupKBExternal(ctx, ext)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				if row != nil {
					entries = append(entries, *row)
				}
			}
			return jsonResult(kbDetailPayload(entries, omitted))
		})
}

// splitKBDetailIDs keeps the first 5 ids. external_id is a separate lookup and does not use a slot.
func splitKBDetailIDs(ids []int64) (kept, omitted []int64) {
	if len(ids) <= kbDetailIDCap {
		return ids, nil
	}
	return ids[:kbDetailIDCap], ids[kbDetailIDCap:]
}

func kbDetailPayload(entries []db.KBEntry, omitted []int64) map[string]any {
	var listed any = entries
	if len(entries) == 0 {
		listed = []any{}
	}
	out := map[string]any{
		"entries":     listed,
		"omitted_ids": omitted,
		"note":        kbClueNote,
	}
	if len(omitted) > 0 {
		out["limit_note"] = kbDetailLimitNote
	}
	return out
}

func (t *ToolSet) lookupKBExternal(ctx context.Context, ext string) (*db.KBEntry, error) {
	row, err := t.pg.GetKBEntryByExternalID(ext)
	if err != nil || row != nil || KBOnDemand == nil || !kbCVEPattern.MatchString(ext) {
		return row, err
	}
	if err := KBOnDemand(ctx, strings.ToUpper(ext)); err != nil {
		return nil, nil
	}
	return t.pg.GetKBEntryByExternalID(ext)
}

func (t *ToolSet) matchAssetVulns() actool.CoreTool {
	return readTool("match_asset_vulns",
		"用资产指纹碰撞知识库，只返回高危/严重或在野利用条目。"+kbClueNote,
		obj(map[string]any{
			"asset_ids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "资产 id"},
			"products":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "技术栈/产品名"},
			"limit":     intp("每个资产返回的条目数，默认 3"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.pg == nil {
				return actool.Errorf("知识库未启用"), nil
			}
			var a struct {
				AssetIDs []json.RawMessage `json:"asset_ids"`
				Products []string          `json:"products"`
				Limit    int               `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			limit := a.Limit
			if limit <= 0 {
				limit = 3
			}
			var fps []db.KBFingerprint
			if ids := pidList(a.AssetIDs); len(ids) > 0 {
				if t.as == nil {
					return actool.Errorf("资产库未启用"), nil
				}
				assets, err := t.as.GetByIDs(ids)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				for _, asset := range assets {
					techs := append([]string{}, asset.Technologies...)
					if asset.ServiceName != "" {
						techs = append(techs, asset.ServiceName)
					}
					if asset.AppName != "" {
						techs = append(techs, asset.AppName)
					}
					fps = append(fps, db.KBFingerprint{ID: asset.ID, Techs: techs})
				}
			}
			if len(a.Products) > 0 {
				fps = append(fps, db.KBFingerprint{ID: 0, Techs: a.Products})
			}
			if len(fps) == 0 {
				return jsonResult(map[string]any{"matches": []any{}, "note": kbClueNote})
			}
			matches, err := t.pg.MatchAssetsAgainstKB(fps, limit)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{"matches": kbMatchBriefs(matches), "note": kbClueNote})
		})
}

func kbListBriefs(entries []db.KBEntry) []map[string]any {
	out := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		out = append(out, map[string]any{
			"id": e.ID, "external_id": e.ExternalID, "title": e.Title, "severity": e.Severity,
			"kind": e.Kind, "actively_exploited": e.ActivelyExploited, "has_poc": e.HasPoC,
			"products": e.Products, "summary": e.Summary,
		})
	}
	return out
}

func kbMatchBriefs(matches []db.KBAssetMatch) []map[string]any {
	out := make([]map[string]any, 0, len(matches))
	for _, m := range matches {
		tops := make([]map[string]any, 0, len(m.TopEntries))
		for _, e := range m.TopEntries {
			tops = append(tops, map[string]any{
				"id": e.ID, "external_id": e.ExternalID, "title": e.Title,
				"severity": e.Severity, "has_poc": e.HasPoC, "actively_exploited": e.ActivelyExploited,
			})
		}
		out = append(out, map[string]any{
			"asset_id": m.AssetID, "matched_tech": m.MatchedTech,
			"high_vuln_count": m.HighVulnCount, "top_entries": tops,
		})
	}
	return out
}

func (t *ToolSet) distillFindingToKB() actool.CoreTool {
	return writeTool("distill_finding_to_kb",
		"把已确认的漏洞脱敏沉淀进知识库，变成可复用的检测线索。误报不要调用。已关联知识条目时优先 enrich_existing，否则 new_entry。",
		obj(map[string]any{
			"finding_id":          idp("漏洞 id"),
			"mode":                str("auto|enrich_existing|new_entry，默认 auto"),
			"target_kb_id":        idp("enrich_existing 时要补充的知识条目 id"),
			"bypass_or_key_trick": str("可复用的绕过或关键技巧，写入补充说明"),
			"remediation_note":    str("修复说明"),
		}, "finding_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if t.pg == nil {
				return actool.Errorf("知识库未启用"), nil
			}
			if DistillFindingToKB == nil {
				return actool.Errorf("知识库沉淀未启用"), nil
			}
			var a struct {
				FindingID   json.RawMessage `json:"finding_id"`
				Mode        string          `json:"mode"`
				TargetKBID  json.RawMessage `json:"target_kb_id"`
				Bypass      string          `json:"bypass_or_key_trick"`
				Remediation string          `json:"remediation_note"`
			}
			_ = json.Unmarshal(in, &a)
			id := pid(a.FindingID)
			if id <= 0 {
				return actool.Errorf("finding_id 无效"), nil
			}
			f, err := t.pg.GetFinding(id)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if f == nil {
				return actool.Errorf("漏洞不存在"), nil
			}
			if f.Status == db.FindingFalsePositive {
				return actool.Errorf("误报不沉淀到知识库"), nil
			}
			if t.taskID > 0 && (f.TaskID == nil || *f.TaskID != t.taskID) {
				return actool.Errorf("该漏洞不属于当前任务"), nil
			}
			var notes []string
			if s := strings.TrimSpace(a.Bypass); s != "" {
				notes = append(notes, "绕过或关键技巧：\n"+s)
			}
			if s := strings.TrimSpace(a.Remediation); s != "" {
				notes = append(notes, "修复说明：\n"+s)
			}
			mode := strings.TrimSpace(a.Mode)
			if mode == "" {
				mode = "auto"
			}
			kbID, nkey, err := DistillFindingToKB(ctx, id, mode, pid(a.TargetKBID), strings.Join(notes, "\n\n"))
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{"finding_id": id, "kb_entry_id": kbID, "nkey": nkey, "mode": mode})
		})
}

func assetItemTechs(item assetInputItem) []string {
	var techs []string
	techs = append(techs, item.Technologies...)
	if item.ServiceName != "" {
		techs = append(techs, item.ServiceName)
	}
	if item.AppName != "" {
		techs = append(techs, item.AppName)
	}
	return techs
}

func (t *ToolSet) kbHints(fps []db.KBFingerprint) []map[string]any {
	if t.pg == nil || len(fps) == 0 {
		return nil
	}
	matches, err := t.pg.MatchAssetsAgainstKB(fps, 3)
	if err != nil || len(matches) == 0 {
		return nil
	}
	briefs := kbMatchBriefs(matches)
	for _, item := range briefs {
		item["tip"] = "可用 get_knowledge_detail / match_asset_vulns 查看检测思路。" + kbClueNote
	}
	return briefs
}
