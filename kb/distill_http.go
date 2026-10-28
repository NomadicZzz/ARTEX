package kb

import (
	"encoding/base64"
	"strings"
	"unicode/utf8"
)

const responseIndicatorLimit = 1024

var sensitiveHeaderNames = map[string]bool{
	"cookie": true, "authorization": true, "x-api-key": true,
	"x-auth-token": true, "proxy-authorization": true, "set-cookie": true,
}

var keepResponseHeaders = map[string]bool{
	"server": true, "x-powered-by": true, "content-type": true,
}

// RedactHTTPPacket masks a raw HTTP request and response for reuse as a PoC
// template. The request line, path, and non-secret headers stay. Host, cookies,
// and credentials become placeholders. The response keeps the status line and
// fingerprint headers, and the body is cut to the first useful indicator.
func RedactHTTPPacket(rawReq, rawResp string) (string, string) {
	return redactRequest(rawReq), redactResponse(rawResp)
}

// FormatPoCSnippet joins a redacted request and response into the snippet stored
// on a knowledge entry.
func FormatPoCSnippet(req, resp string) string {
	req = strings.TrimSpace(req)
	resp = strings.TrimSpace(resp)
	if req == "" && resp == "" {
		return ""
	}
	var b strings.Builder
	if req != "" {
		b.WriteString("# Request\n")
		b.WriteString(req)
	}
	if resp != "" {
		if b.Len() > 0 {
			b.WriteString("\n\n")
		}
		b.WriteString("# Expected Response Indicator\n")
		b.WriteString(resp)
	}
	return b.String()
}

func redactRequest(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	head, body := splitHTTP(raw)
	lines := splitHTTPLines(head)
	if len(lines) == 0 {
		return RedactSensitive(raw)
	}
	lines[0] = redactRequestLine(lines[0])
	for i := 1; i < len(lines); i++ {
		name, value, ok := splitHeader(lines[i])
		if !ok {
			lines[i] = RedactSensitive(lines[i])
			continue
		}
		switch {
		case strings.EqualFold(name, "host"):
			lines[i] = "Host: <target-host>"
		case sensitiveHeaderNames[strings.ToLower(name)]:
			lines[i] = name + ": " + redactCredential(value)
		default:
			lines[i] = name + ": " + RedactSensitive(value)
		}
	}
	out := strings.Join(lines, "\n")
	if strings.TrimSpace(body) != "" {
		out += "\n\n" + RedactSensitive(body)
	}
	return out
}

func redactResponse(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	head, body := splitHTTP(raw)
	lines := splitHTTPLines(head)
	if len(lines) == 0 {
		return clipBytes(RedactSensitive(raw), responseIndicatorLimit)
	}
	var kept []string
	kept = append(kept, lines[0])
	for _, line := range lines[1:] {
		name, value, ok := splitHeader(line)
		if !ok {
			continue
		}
		lower := strings.ToLower(name)
		switch {
		case sensitiveHeaderNames[lower]:
			kept = append(kept, name+": <redacted>")
		case keepResponseHeaders[lower]:
			kept = append(kept, name+": "+RedactSensitive(value))
		}
	}
	out := strings.Join(kept, "\n")
	if indicator := responseIndicator(body); indicator != "" {
		out += "\n\n" + indicator
	}
	return out
}

func redactRequestLine(line string) string {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return RedactSensitive(line)
	}
	target := fields[1]
	if strings.Contains(target, "://") {
		target = urlHostRe.ReplaceAllStringFunc(target, func(m string) string {
			sub := urlHostRe.FindStringSubmatch(m)
			if len(sub) < 3 || strings.Contains(sub[2], "<") {
				return m
			}
			rest := strings.TrimPrefix(m, sub[1]+sub[2])
			return sub[1] + "<target-host>" + rest
		})
		fields[1] = target
	}
	return strings.Join(fields, " ")
}

func redactCredential(value string) string {
	value = strings.TrimSpace(value)
	scheme, token := "", value
	if i := strings.IndexAny(value, " \t"); i > 0 {
		scheme, token = value[:i], strings.TrimSpace(value[i+1:])
	}
	parts := strings.Split(token, ".")
	if len(parts) == 3 && strings.HasPrefix(parts[0], "eyJ") && jwtAlgNone(parts[0]) {
		kept := parts[0] + ".<redacted>.<redacted>"
		if scheme != "" {
			return scheme + " " + kept
		}
		return kept
	}
	return "<redacted>"
}

func jwtAlgNone(header string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		raw, err = base64.URLEncoding.DecodeString(header)
		if err != nil {
			return false
		}
	}
	s := strings.ToLower(string(raw))
	return strings.Contains(s, `"alg":"none"`) || strings.Contains(s, `"alg": "none"`)
}

func splitHTTP(raw string) (head, body string) {
	if i := strings.Index(raw, "\r\n\r\n"); i >= 0 {
		return raw[:i], raw[i+4:]
	}
	if i := strings.Index(raw, "\n\n"); i >= 0 {
		return raw[:i], raw[i+2:]
	}
	return raw, ""
}

func splitHTTPLines(head string) []string {
	head = strings.ReplaceAll(head, "\r\n", "\n")
	lines := strings.Split(head, "\n")
	var out []string
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		out = append(out, line)
	}
	return out
}

func splitHeader(line string) (name, value string, ok bool) {
	i := strings.IndexByte(line, ':')
	if i <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:]), true
}

func responseIndicator(body string) string {
	body = strings.TrimSpace(body)
	if body == "" {
		return ""
	}
	lower := strings.ToLower(body)
	keys := []string{"traceback", "exception", "syntax error", "sql", "ora-", "uid=", "stack", "error"}
	cut := body
	for _, key := range keys {
		if i := strings.Index(lower, key); i >= 0 {
			start := i - 80
			if start < 0 {
				start = 0
			}
			cut = body[start:]
			break
		}
	}
	return clipBytes(RedactSensitive(cut), responseIndicatorLimit)
}

func clipBytes(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	b := []byte(s)[:n]
	for len(b) > 0 && !utf8.Valid(b) {
		b = b[:len(b)-1]
	}
	return string(b)
}
