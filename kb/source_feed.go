package kb

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/url"
	"strings"

	"github.com/Autumn-27/artex/db"
)

type rssDoc struct {
	Channel struct {
		Items []rssItem `xml:"item"`
	} `xml:"channel"`
	Entries []atomEntry `xml:"entry"`
}

type rssItem struct {
	Title   string `xml:"title"`
	Link    string `xml:"link"`
	Desc    string `xml:"description"`
	PubDate string `xml:"pubDate"`
	GUID    string `xml:"guid"`
}

type atomEntry struct {
	Title   string `xml:"title"`
	ID      string `xml:"id"`
	Updated string `xml:"updated"`
	Summary string `xml:"summary"`
	Content string `xml:"content"`
	Links   []struct {
		Href string `xml:"href,attr"`
	} `xml:"link"`
}

// ParseFeed accepts RSS 2.0 or Atom.
func ParseFeed(body []byte, sourceKey string) ([]Draft, error) {
	var doc rssDoc
	if err := xml.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	var out []Draft
	for _, item := range doc.Channel.Items {
		title := strings.TrimSpace(item.Title)
		if title == "" {
			continue
		}
		link := strings.TrimSpace(item.Link)
		summary := stripHTML(item.Desc)
		cve := upperCVE(title + " " + summary)
		ext := cve
		nkey := ""
		if ext == "" {
			ext = strings.TrimSpace(item.GUID)
			if ext == "" {
				ext = link
			}
			nkey = "method:" + slug(title)
		}
		var refs []db.KBReference
		if link != "" {
			refs = []db.KBReference{{URL: link, Title: title}}
		}
		out = append(out, Draft{
			NKey:           nkey,
			ExternalID:     ext,
			SourceKey:      sourceKey,
			Kind:           feedKind(cve),
			Severity:       "info",
			Title:          title,
			Summary:        clip(summary, 1500),
			DetectionGuide: "RSS/公告只提供背景。检测思路需结合受影响产品在授权范围内验证，文章本身不是漏洞证据。",
			References:     refs,
			PublishedAt:    parseTimeFlexible(item.PubDate),
		})
	}
	for _, entry := range doc.Entries {
		title := strings.TrimSpace(entry.Title)
		if title == "" {
			continue
		}
		summary := stripHTML(entry.Summary)
		if summary == "" {
			summary = stripHTML(entry.Content)
		}
		link := strings.TrimSpace(entry.ID)
		for _, l := range entry.Links {
			if l.Href != "" {
				link = l.Href
				break
			}
		}
		cve := upperCVE(title + " " + summary)
		ext := cve
		nkey := ""
		if ext == "" {
			ext = strings.TrimSpace(entry.ID)
			nkey = "method:" + slug(title)
		}
		var refs []db.KBReference
		if strings.HasPrefix(link, "http") {
			refs = []db.KBReference{{URL: link, Title: title}}
		}
		out = append(out, Draft{
			NKey:           nkey,
			ExternalID:     ext,
			SourceKey:      sourceKey,
			Kind:           feedKind(cve),
			Severity:       "info",
			Title:          title,
			Summary:        clip(summary, 1500),
			DetectionGuide: "RSS/公告只提供背景。检测思路需结合受影响产品在授权范围内验证，文章本身不是漏洞证据。",
			References:     refs,
			PublishedAt:    parseTimeFlexible(entry.Updated),
		})
	}
	return out, nil
}

func feedKind(cve string) string {
	if cve != "" {
		return "cve"
	}
	return "methodology"
}

func syncGit(ctx context.Context, c *Client, src db.KBSource, emit func(Draft) error) (string, error) {
	cfg := configMap(src.Config)
	repo := configString(cfg, "repo_url", "")
	if repo == "" {
		return src.Cursor, fmt.Errorf("repo_url 未配置")
	}
	owner, name, err := parseGitHubRepo(repo)
	if err != nil {
		return src.Cursor, err
	}
	branch := configString(cfg, "branch", "main")
	prefix := strings.Trim(configString(cfg, "path", ""), "/")
	treeURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/git/trees/%s?recursive=1", owner, name, url.PathEscape(branch))
	body, _, err := c.GetBytes(ctx, treeURL, map[string]string{"Accept": "application/vnd.github+json"}, 8<<20)
	if err != nil {
		return src.Cursor, err
	}
	var tree struct {
		SHA  string `json:"sha"`
		Tree []struct {
			Path string `json:"path"`
			Type string `json:"type"`
			Size int    `json:"size"`
		} `json:"tree"`
	}
	if err := json.Unmarshal(body, &tree); err != nil {
		return src.Cursor, err
	}
	if tree.SHA != "" && tree.SHA == src.Cursor {
		return tree.SHA, nil
	}
	n := 0
	for _, item := range tree.Tree {
		if ctx.Err() != nil {
			return tree.SHA, ctx.Err()
		}
		if item.Type != "blob" || !strings.HasSuffix(strings.ToLower(item.Path), ".md") {
			continue
		}
		if prefix != "" && item.Path != prefix && !strings.HasPrefix(item.Path, prefix+"/") {
			continue
		}
		if item.Size > 256<<10 {
			continue
		}
		if n >= 200 {
			break
		}
		raw := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s", owner, name, branch, item.Path)
		md, _, err := c.GetBytes(ctx, raw, nil, 256<<10)
		if err != nil {
			continue
		}
		n++
		title := markdownTitle(string(md), item.Path)
		if err := emit(Draft{
			NKey:           "method:" + slug(item.Path),
			ExternalID:     item.Path,
			SourceKey:      src.Key,
			Kind:           "methodology",
			Severity:       "info",
			Title:          title,
			Summary:        clip(stripMarkdown(string(md)), 800),
			DetectionGuide: clip(string(md), 8000),
			References:     []db.KBReference{{URL: raw, Title: title}},
		}); err != nil {
			return tree.SHA, err
		}
	}
	if tree.SHA == "" {
		tree.SHA = "fetched"
	}
	return tree.SHA, nil
}

func parseGitHubRepo(raw string) (owner, name string, err error) {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimSuffix(raw, ".git")
	raw = strings.TrimPrefix(raw, "https://github.com/")
	raw = strings.TrimPrefix(raw, "http://github.com/")
	raw = strings.TrimPrefix(raw, "git@github.com:")
	raw = strings.Trim(raw, "/")
	parts := strings.Split(raw, "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("无法解析 GitHub 仓库 %s", raw)
	}
	return parts[0], parts[1], nil
}

func markdownTitle(body, path string) string {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			return strings.TrimSpace(strings.TrimLeft(line, "#"))
		}
	}
	base := path
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	return strings.TrimSuffix(base, ".md")
}

func stripMarkdown(s string) string {
	s = strings.ReplaceAll(s, "#", " ")
	return strings.Join(strings.Fields(s), " ")
}
