package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestDistillFindingToKBTool(t *testing.T) {
	d := testDB(t)
	t.Cleanup(func() { d.Close() })
	prev := DistillFindingToKB
	t.Cleanup(func() { DistillFindingToKB = prev })

	fp, err := d.AddFinding(0, 0, "info", "误报样本", "low", "不是漏洞", "", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	okID, err := d.AddFinding(0, 0, "sqli", "可沉淀样本", "high", "摘要", "证据", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM findings WHERE id=$1 OR id=$2`, fp, okID)
	})
	if _, err = d.SetFindingStatus(fp, db.FindingFalsePositive); err != nil {
		t.Fatal(err)
	}

	ts := NewToolSet(nil, "test")
	ts.pg = d
	tool := ts.distillFindingToKB()

	DistillFindingToKB = func(context.Context, int64, string, int64, string) (int64, string, error) {
		t.Fatal("false positive must not reach the writer")
		return 0, "", nil
	}
	raw, _ := json.Marshal(map[string]any{"finding_id": fp})
	res, err := tool.Call(context.Background(), raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Flatten(), "误报") {
		t.Fatalf("false positive result: %s", res.Flatten())
	}

	ts.SetTaskID(1)
	raw, _ = json.Marshal(map[string]any{"finding_id": okID})
	res, err = tool.Call(context.Background(), raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Flatten(), "不属于当前任务") {
		t.Fatalf("task scope result: %s", res.Flatten())
	}

	ts.SetTaskID(0)
	var gotNotes string
	DistillFindingToKB = func(_ context.Context, findingID int64, mode string, target int64, notes string) (int64, string, error) {
		if findingID != okID || mode != "auto" || target != 9 {
			t.Fatalf("callback args id=%d mode=%s target=%d", findingID, mode, target)
		}
		gotNotes = notes
		return 42, "finding:42", nil
	}
	raw, _ = json.Marshal(map[string]any{"finding_id": okID, "target_kb_id": 9, "remediation_note": "升级"})
	res, err = tool.Call(context.Background(), raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err = json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
		t.Fatalf("unmarshal %s: %v", res.Flatten(), err)
	}
	if out["kb_entry_id"] != float64(42) || out["nkey"] != "finding:42" {
		t.Fatalf("result=%s", res.Flatten())
	}
	if !strings.Contains(gotNotes, "升级") {
		t.Fatalf("notes=%q", gotNotes)
	}

	bound := map[string]bool{}
	for _, seed := range BuiltinToolSeeds() {
		if seed.Key != "distill_finding_to_kb" {
			continue
		}
		for _, key := range seed.Agents {
			bound[key] = true
		}
	}
	for _, key := range []string{"worker", "mainagent", "pentest", "auto"} {
		if !bound[key] {
			t.Fatalf("missing default binding %s in %#v", key, bound)
		}
	}
	if bound["planner"] {
		t.Fatalf("planner should not distill by default: %#v", bound)
	}
}
