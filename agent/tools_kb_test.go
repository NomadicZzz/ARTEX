package agent

import (
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestBuiltinKnowledgeToolsBound(t *testing.T) {
	bound := map[string]map[string]bool{}
	for _, seed := range BuiltinToolSeeds() {
		set := map[string]bool{}
		for _, agentKey := range seed.Agents {
			set[agentKey] = true
		}
		bound[seed.Key] = set
	}
	for _, key := range []string{"search_knowledge", "get_knowledge_detail"} {
		if !bound[key]["planner"] || !bound[key]["worker"] || !bound[key]["mainagent"] || !bound[key]["pentest"] || !bound[key]["auto"] {
			t.Fatalf("%s agents = %#v", key, bound[key])
		}
	}
	if !bound["match_asset_vulns"]["planner"] || !bound["match_asset_vulns"]["worker"] || !bound["match_asset_vulns"]["pentest"] {
		t.Fatalf("match agents = %#v", bound["match_asset_vulns"])
	}
	if bound["match_asset_vulns"]["mainagent"] || bound["match_asset_vulns"]["auto"] {
		t.Fatalf("match should stay off mainagent/auto: %#v", bound["match_asset_vulns"])
	}
}

func TestKBDetailLimitNote(t *testing.T) {
	kept, omitted := splitKBDetailIDs([]int64{1, 2, 3, 4, 5, 6, 7})
	if len(kept) != 5 || kept[0] != 1 || kept[4] != 5 || len(omitted) != 2 || omitted[0] != 6 || omitted[1] != 7 {
		t.Fatalf("kept=%v omitted=%v", kept, omitted)
	}
	over := kbDetailPayload(nil, omitted)
	entries, ok := over["entries"].([]any)
	if !ok || len(entries) != 0 {
		t.Fatalf("empty entries = %#v", over["entries"])
	}
	if over["limit_note"] != kbDetailLimitNote || over["note"] != kbClueNote {
		t.Fatalf("truncated payload = %#v", over)
	}

	kept, omitted = splitKBDetailIDs([]int64{1, 2, 3, 4, 5})
	if len(kept) != 5 || omitted != nil {
		t.Fatalf("under cap kept=%v omitted=%v", kept, omitted)
	}
	under := kbDetailPayload([]db.KBEntry{{ID: 1}}, omitted)
	if _, ok := under["limit_note"]; ok {
		t.Fatalf("limit_note set for %d ids", len(kept))
	}
	if under["note"] != kbClueNote {
		t.Fatalf("note = %#v", under["note"])
	}
}

func TestGetKnowledgeDetailCapWording(t *testing.T) {
	var desc string
	for _, seed := range BuiltinToolSeeds() {
		if seed.Key == "get_knowledge_detail" {
			desc = seed.Desc
		}
	}
	if !strings.Contains(desc, "按 id 最多 5 条") || !strings.Contains(desc, "external_id 另计") {
		t.Fatalf("desc = %s", desc)
	}
}
