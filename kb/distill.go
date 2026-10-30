package kb

import (
	"encoding/json"
	"regexp"
	"strings"
)

var (
	urlHostRe = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://)([^/\s]+)`)
	ipv4Re    = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	// Three or more colon groups, or a compressed "::". Two-group times like
	// 12:30:00 stay intact.
	ipv6Re  = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{1,4}:){3,7}[0-9a-f]{1,4}\b|\b[0-9a-f:]{0,16}::[0-9a-f:]{0,20}\b`)
	emailRe = regexp.MustCompile(`(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b`)
	phoneRe = regexp.MustCompile(`\b1[3-9]\d{9}\b`)
	// The optional quote covers JSON keys such as "password":"value".
	secretRe = regexp.MustCompile(`(?i)(password|passwd|token|secret|api[_-]?key|authorization)(")?(\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s&,"']+)`)
	// Cloud access keys: Aliyun LTAI, Tencent AKID, AWS AKIA.
	cloudAKRe = regexp.MustCompile(`\b(?:LTAI[A-Za-z0-9]{12,24}|AKID[A-Za-z0-9]{13,24}|AKIA[0-9A-Z]{16})\b`)
	// DingTalk corp id, for example ding5ac93f66828c8f3835c2f4657eb6378f.
	corpIDRe      = regexp.MustCompile(`\bding[0-9a-fA-F]{24,40}\b`)
	proxyURLRe    = regexp.MustCompile(`(?i)\bsocks[45]h?://[^\s"'` + "`" + `<>]+`)
	dockerHostRe  = regexp.MustCompile(`(?i)host\.docker\.internal`)
	piiFieldRe    = regexp.MustCompile(`(?i)\b(user_name|real_name|employee_name|organ_simple_name|organ_show_name|corp_name)\s*([:=：]\s*"?)([^",\n\r}]+)("?)`)
	cnOrgEntityRe = regexp.MustCompile(`[\p{Han}]{2,12}(?:肿瘤医院|人民医院|第一医院|中心医院|中医院|附属医院|妇幼保健院|银行股份有限公司|集团股份有限公司|政务服务局|大数据局)`)
)

// RedactSensitive masks hosts, IP addresses, emails, phone numbers, and common
// secret assignments before a finding is sent to an LLM or stored as methodology text.
// Placeholders already wrapped in angle brackets are left alone.
func RedactSensitive(s string) string {
	s = cloudAKRe.ReplaceAllString(s, "<cloud-ak>")
	s = corpIDRe.ReplaceAllString(s, "<corp-id>")
	s = proxyURLRe.ReplaceAllString(s, "<proxy-url>")
	s = dockerHostRe.ReplaceAllString(s, "<proxy-url>")
	s = urlHostRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := urlHostRe.FindStringSubmatch(m)
		if len(sub) < 3 || strings.Contains(sub[2], "<") {
			return m
		}
		return sub[1] + "<host>"
	})
	s = ipv4Re.ReplaceAllString(s, "<ip>")
	s = ipv6Re.ReplaceAllString(s, "<ip>")
	s = emailRe.ReplaceAllString(s, "<email>")
	s = phoneRe.ReplaceAllString(s, "<phone>")
	s = piiFieldRe.ReplaceAllString(s, `${1}${2}<redacted>${4}`)
	s = secretRe.ReplaceAllString(s, `${1}${2}${3}<redacted>`)
	s = cnOrgEntityRe.ReplaceAllString(s, "<org-name>")
	return s
}

const DistillSystem = `你是授权安全评估的知识整理助手。根据给定材料，输出检测指导，帮助测试人员在已授权目标上判断是否需要验证。
只输出一个 JSON 对象，不要 Markdown。字段：
{"summary":"一两句公开摘要","detection_guide":"检测时看什么、如何对照版本与行为，不要发明新的利用链","products":["受影响产品"],"vulnclass":"漏洞类别"}
材料里没有的利用步骤不要编造。把具体主机、IP、口令写成占位符。`

// DistillFields is the JSON an LLM is asked to return. CVE sync only fills the
// first four fields. Finding distillation adds the rest; empty ones stay out of
// the old JSON so existing callers keep working.
type DistillFields struct {
	Summary          string   `json:"summary"`
	DetectionGuide   string   `json:"detection_guide"`
	Products         []string `json:"products"`
	VulnClass        string   `json:"vulnclass"`
	Title            string   `json:"title,omitempty"`
	Kind             string   `json:"kind,omitempty"`
	Severity         string   `json:"severity,omitempty"`
	Tags             []string `json:"tags,omitempty"`
	PocSnippet       string   `json:"poc_snippet,omitempty"`
	Remediation      string   `json:"remediation,omitempty"`
	SuggestedMode    string   `json:"suggested_mode,omitempty"`
	AffectedVersions string   `json:"affected_versions,omitempty"`
	ExternalID       string   `json:"external_id,omitempty"`
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
