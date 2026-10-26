package kb

import (
	"encoding/json"
	"regexp"
	"strings"
)

var (
	urlHostRe = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://)([^/\s]+)`)
	ipv4Re    = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	secretRe  = regexp.MustCompile(`(?i)(password|passwd|token|secret|api[_-]?key|authorization)\s*([:=])\s*([^\s&,"']+)`)
)

// RedactSensitive masks hosts, IPv4 addresses, and common secret assignments
// before a finding is sent to an LLM or stored as methodology text.
func RedactSensitive(s string) string {
	s = urlHostRe.ReplaceAllString(s, `${1}<host>`)
	s = ipv4Re.ReplaceAllString(s, "<ip>")
	s = secretRe.ReplaceAllString(s, `$1$2<redacted>`)
	return s
}

const DistillSystem = `你是授权安全评估的知识整理助手。根据给定材料，输出检测指导，帮助测试人员在已授权目标上判断是否需要验证。
只输出一个 JSON 对象，不要 Markdown。字段：
{"summary":"一两句公开摘要","detection_guide":"检测时看什么、如何对照版本与行为，不要发明新的利用链","products":["受影响产品"],"vulnclass":"漏洞类别"}
材料里没有的利用步骤不要编造。把具体主机、IP、口令写成占位符。`

// DistillFields is the JSON an LLM is asked to return.
type DistillFields struct {
	Summary        string   `json:"summary"`
	DetectionGuide string   `json:"detection_guide"`
	Products       []string `json:"products"`
	VulnClass      string   `json:"vulnclass"`
}

// ParseDistillJSON extracts the object even if the model wrapped it in prose.
func ParseDistillJSON(raw string) (DistillFields, error) {
	raw = strings.TrimSpace(raw)
	if i := strings.Index(raw, "{"); i >= 0 {
		if j := strings.LastIndex(raw, "}"); j > i {
			raw = raw[i : j+1]
		}
	}
	var out DistillFields
	err := json.Unmarshal([]byte(raw), &out)
	return out, err
}
