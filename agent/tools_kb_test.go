package agent

import "testing"

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
