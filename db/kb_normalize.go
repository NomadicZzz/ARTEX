package db

import (
	"regexp"
	"strings"
	"unicode"
)

// Product aliases collapse CPE names, Nuclei tags, and Chinese product names onto
// one token so they intersect assets.technologies / service_name / app_name.
var kbProductAliases = map[string]string{
	"spring cloud gateway":        "spring-cloud-gateway",
	"springcloudgateway":          "spring-cloud-gateway",
	"spring-cloud-gateway":        "spring-cloud-gateway",
	"vmware spring cloud gateway": "spring-cloud-gateway",
	"apache log4j":                "log4j",
	"log4j2":                      "log4j",
	"log4j":                       "log4j",
	"alibaba fastjson":            "fastjson",
	"fastjson":                    "fastjson",
	"com.alibaba.fastjson":        "fastjson",
	"apache shiro":                "shiro",
	"shiro":                       "shiro",
	"nacos":                       "nacos",
	"alibaba nacos":               "nacos",
	"泛微":                          "weaver-ecology",
	"泛微ecology":                   "weaver-ecology",
	"泛微e-cology":                  "weaver-ecology",
	"泛微oa":                        "weaver-ecology",
	"weaver ecology":              "weaver-ecology",
	"weaver e-cology":             "weaver-ecology",
	"weaver-e-cology":             "weaver-ecology",
	"weaver-ecology":              "weaver-ecology",
	"e-cology":                    "weaver-ecology",
	"ecology":                     "weaver-ecology",
	"致远":                          "seeyon-oa",
	"致远oa":                        "seeyon-oa",
	"seeyon":                      "seeyon-oa",
	"seeyon-oa":                   "seeyon-oa",
	"用友":                          "yonyou-nc",
	"用友nc":                        "yonyou-nc",
	"yonyou":                      "yonyou-nc",
	"yonyou-nc":                   "yonyou-nc",
	"帆软":                          "fanruan",
	"finereport":                  "fanruan",
	"finebi":                      "fanruan",
	"fanruan":                     "fanruan",
	"thinkphp":                    "thinkphp",
	"think php":                   "thinkphp",
	"apache struts":               "struts2",
	"struts2":                     "struts2",
	"struts":                      "struts2",
	"spring":                      "spring",
	"spring boot":                 "spring-boot",
	"springboot":                  "spring-boot",
	"spring-boot":                 "spring-boot",
	"jenkins":                     "jenkins",
	"gitlab":                      "gitlab",
	"confluence":                  "confluence",
	"atlassian confluence":        "confluence",
	"jira":                        "jira",
	"weblogic":                    "weblogic",
	"oracle weblogic":             "weblogic",
	"tomcat":                      "tomcat",
	"apache tomcat":               "tomcat",
	"nginx":                       "nginx",
	"redis":                       "redis",
	"mysql":                       "mysql",
	"postgresql":                  "postgresql",
	"mongodb":                     "mongodb",
	"elasticsearch":               "elasticsearch",
	"exchange":                    "exchange",
	"microsoft exchange":          "exchange",
	"openssh":                     "openssh",
	"openssl":                     "openssl",
}

var (
	kbVersionSuffix = regexp.MustCompile(`(?i)[:/\s]+v?\d+(\.\d+){0,3}\s*$`)
	kbNonSlug       = regexp.MustCompile(`[^a-z0-9]+`)
	kbCPE           = regexp.MustCompile(`(?i)^cpe:2\.3:[aho\*]+:([^:]+):([^:]+)`)
)

// NormalizeProduct maps one component string onto the knowledge-base token.
// Empty input and tokens shorter than 2 characters return "".
func NormalizeProduct(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if m := kbCPE.FindStringSubmatch(s); len(m) == 3 {
		product := strings.ReplaceAll(strings.ToLower(m[2]), "_", " ")
		if tok := normalizeProductKey(product); tok != "" {
			return tok
		}
		vendor := strings.ReplaceAll(strings.ToLower(m[1]), "_", " ")
		return normalizeProductKey(vendor + " " + product)
	}
	return normalizeProductKey(s)
}

func normalizeProductKey(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = kbVersionSuffix.ReplaceAllString(s, "")
	s = strings.ReplaceAll(s, "_", " ")
	s = strings.Join(strings.Fields(s), " ")
	s = strings.Trim(s, " .-")
	if s == "" {
		return ""
	}
	if tok, ok := kbProductAliases[s]; ok {
		return tok
	}
	compact := strings.ReplaceAll(strings.ReplaceAll(s, " ", ""), "-", "")
	if tok, ok := kbProductAliases[compact]; ok {
		return tok
	}
	hyphen := strings.ReplaceAll(s, " ", "-")
	if tok, ok := kbProductAliases[hyphen]; ok {
		return tok
	}
	// Chinese names that contain a known alias as a substring (泛微 e-cology 9.0).
	for key, tok := range kbProductAliases {
		if containsHan(key) && strings.Contains(s, key) {
			return tok
		}
	}
	slug := strings.Trim(kbNonSlug.ReplaceAllString(s, "-"), "-")
	if len(slug) < 2 {
		return ""
	}
	if tok, ok := kbProductAliases[slug]; ok {
		return tok
	}
	return slug
}

func containsHan(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Han, r) {
			return true
		}
	}
	return false
}

// NormalizeProducts dedups and normalizes a list, dropping empties.
func NormalizeProducts(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, raw := range in {
		for _, part := range splitProductParts(raw) {
			tok := NormalizeProduct(part)
			if tok == "" || seen[tok] {
				continue
			}
			seen[tok] = true
			out = append(out, tok)
		}
	}
	return out
}

func splitProductParts(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if strings.Contains(raw, ",") {
		return strings.Split(raw, ",")
	}
	return []string{raw}
}

// AssetFingerprints normalizes the component fields stored on an asset.
func AssetFingerprints(technologies []string, serviceName, appName string) []string {
	in := append([]string{}, technologies...)
	if serviceName != "" {
		in = append(in, serviceName)
	}
	if appName != "" {
		in = append(in, appName)
	}
	return NormalizeProducts(in)
}

// broadBaseTechs are stack foundations every asset has. A fingerprint of "nginx"
// or "java" says nothing about which product is running, so it must never pull a
// decade of public CVEs into insert_assets' kb_hints.
var broadBaseTechs = map[string]bool{
	"http": true, "https": true, "tcp": true, "udp": true, "ssl": true, "tls": true,
	"linux": true, "ubuntu": true, "centos": true, "debian": true, "windows": true,
	"java": true, "jdk": true, "php": true, "python": true, "nodejs": true, "go": true,
	"ruby": true, "dotnet": true, "asp.net": true, "aspnet": true, "html": true,
	"javascript": true, "vue": true, "react": true, "jquery": true, "bootstrap": true,
	"nginx": true, "openresty": true, "apache": true, "httpd": true, "iis": true,
	"tomcat": true, "jetty": true, "undertow": true,
	"mysql": true, "mariadb": true, "postgresql": true, "postgres": true,
	"redis": true, "mongodb": true, "memcached": true, "sqlite": true,
	"docker": true, "kubernetes": true, "spring": true,
}

// kbVersionPin matches a fingerprint that names a version, e.g. "nginx/1.18.0" or
// "Fastjson 1.2.47". A version pins the component closely enough to collide.
var kbVersionPin = regexp.MustCompile(`(?i)\d+\.\d+`)

// IsBroadBaseTech reports whether a normalized token is a generic stack foundation
// rather than a specific application, framework or middleware.
func IsBroadBaseTech(token string) bool {
	return broadBaseTechs[strings.ToLower(strings.TrimSpace(token))]
}

// SplitSpecificAndBroadProducts sorts raw fingerprint strings into tokens worth
// colliding (a specific component, or a broad one the raw string pins to a
// version) and broad ones that only describe the stack.
func SplitSpecificAndBroadProducts(rawTechs []string) (specific, broad []string) {
	seen := map[string]bool{}
	for _, raw := range rawTechs {
		pinned := kbVersionPin.MatchString(raw)
		for _, part := range splitProductParts(raw) {
			tok := NormalizeProduct(part)
			if tok == "" || seen[tok] {
				continue
			}
			seen[tok] = true
			if IsBroadBaseTech(tok) && !pinned {
				broad = append(broad, tok)
				continue
			}
			specific = append(specific, tok)
		}
	}
	return specific, broad
}
