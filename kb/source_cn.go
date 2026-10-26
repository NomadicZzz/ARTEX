package kb

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/Autumn-27/artex/db"
)

func syncAVD(ctx context.Context, c *Client, src db.KBSource, emit func(Draft) error) (string, error) {
	cfg := configMap(src.Config)
	listURL := configString(cfg, "feed_url", "https://avd.aliyun.com/high-risk/list")
	pages := configInt(cfg, "page_limit", 3)
	if pages <= 0 || pages > 5 {
		pages = 3
	}
	seen := map[string]bool{}
	var ids []string
	for page := 1; page <= pages; page++ {
		u, err := url.Parse(listURL)
		if err != nil {
			return src.Cursor, err
		}
		q := u.Query()
		q.Set("page", fmt.Sprintf("%d", page))
		u.RawQuery = q.Encode()
		body, _, err := c.GetBytes(ctx, u.String(), nil, 2<<20)
		if err != nil {
			return src.Cursor, err
		}
		found := ParseAVDIDs(body)
		if len(found) == 0 {
			break
		}
		for _, id := range found {
			if seen[id] {
				continue
			}
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if len(ids) > 15 {
		ids = ids[:15]
	}
	var last string
	for _, id := range ids {
		if ctx.Err() != nil {
			return last, ctx.Err()
		}
		detailURL := "https://avd.aliyun.com/detail?id=" + url.QueryEscape(id)
		body, _, err := c.GetBytes(ctx, detailURL, nil, 2<<20)
		if err != nil {
			continue
		}
		d, ok := ParseAVDDetail(body, id, src.Key)
		if !ok {
			continue
		}
		if err := emit(d); err != nil {
			return last, err
		}
		last = id
	}
	if last == "" {
		last = src.Cursor
	}
	return last, nil
}

// ParseAVDIDs finds advisory ids in an HTML list page or a JSON payload.
func ParseAVDIDs(body []byte) []string {
	text := string(body)
	trim := strings.TrimSpace(text)
	if strings.HasPrefix(trim, "{") || strings.HasPrefix(trim, "[") {
		var generic any
		if json.Unmarshal(body, &generic) == nil {
			raw, _ := json.Marshal(generic)
			text = string(raw)
		}
	}
	found := avdPattern.FindAllString(text, -1)
	seen := map[string]bool{}
	var out []string
	for _, id := range found {
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// ParseAVDDetail reads an AVD HTML or JSON detail page.
func ParseAVDDetail(body []byte, id, sourceKey string) (Draft, bool) {
	text := string(body)
	trim := strings.TrimSpace(text)
	title := id
	summary := ""
	if strings.HasPrefix(trim, "{") || strings.HasPrefix(trim, "[") {
		var doc map[string]any
		if json.Unmarshal(body, &doc) == nil {
			if s, _ := doc["title"].(string); s != "" {
				title = s
			}
			if s, _ := doc["name"].(string); s != "" && title == id {
				title = s
			}
			if s, _ := doc["description"].(string); s != "" {
				summary = s
			}
			if s, _ := doc["summary"].(string); s != "" && summary == "" {
				summary = s
			}
		}
	}
	if summary == "" {
		plain := stripHTML(text)
		if i := strings.Index(plain, id); i >= 0 {
			summary = clip(plain[i:], 800)
		} else {
			summary = clip(plain, 800)
		}
	}
	if m := regexpTitle(text); m != "" && (title == id || title == "") {
		title = m
	}
	cve := upperCVE(text)
	aliases := nonEmpty(id)
	ext := cve
	if ext == "" {
		ext = id
		aliases = nil
	}
	if title == "" {
		title = ext
	}
	return Draft{
		ExternalID:     ext,
		Aliases:        aliases,
		SourceKey:      sourceKey,
		Kind:           "cve",
		Severity:       "high",
		Title:          clip(title, 300),
		Summary:        clip(summary, 1500),
		DetectionGuide: "阿里云 AVD 页面只提供公开线索。需要在授权资产上按受影响版本实际触发后才能记为漏洞。",
		References:     []db.KBReference{{URL: "https://avd.aliyun.com/detail?id=" + id, Title: id}},
		Products:       avdProducts(title),
	}, title != "" || ext != ""
}

func regexpTitle(htmlText string) string {
	low := strings.ToLower(htmlText)
	i := strings.Index(low, "<title>")
	if i < 0 {
		return ""
	}
	rest := htmlText[i+len("<title>"):]
	j := strings.Index(strings.ToLower(rest), "</title>")
	if j < 0 {
		return ""
	}
	title := stripHTML(rest[:j])
	title = strings.TrimSpace(strings.Split(title, "-")[0])
	return strings.TrimSpace(title)
}

func avdProducts(title string) []string {
	title = strings.TrimSpace(title)
	if title == "" {
		return nil
	}
	return []string{title}
}

func syncSeebug(ctx context.Context, c *Client, src db.KBSource, emit func(Draft) error) (string, error) {
	cfg := configMap(src.Config)
	feed := configString(cfg, "feed_url", "https://paper.seebug.org/rss/")
	body, _, err := c.GetBytes(ctx, feed, nil, 4<<20)
	if err != nil {
		return src.Cursor, err
	}
	drafts, err := ParseFeed(body, src.Key)
	if err != nil {
		return src.Cursor, err
	}
	var cursor string
	for _, d := range drafts {
		if err := emit(d); err != nil {
			return cursor, err
		}
		if cursor == "" && d.ExternalID != "" {
			cursor = d.ExternalID
		}
	}
	if cursor == "" {
		cursor = src.Cursor
	}
	return cursor, nil
}
