package kb

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

const userAgent = "ARTEX-KB/1.0"

// Client fetches public intelligence. It honors the platform egress proxy and
// refuses to disable TLS verification.
type Client struct {
	Proxy func() string

	mu   sync.Mutex
	next time.Time
	gap  time.Duration
}

func (c *Client) interval() time.Duration {
	if c.gap > 0 {
		return c.gap
	}
	return 200 * time.Millisecond
}

func (c *Client) wait(ctx context.Context) error {
	c.mu.Lock()
	gap := c.interval()
	wait := time.Until(c.next)
	c.next = time.Now().Add(gap)
	c.mu.Unlock()
	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (c *Client) transport() *http.Transport {
	tr := &http.Transport{Proxy: http.ProxyFromEnvironment}
	raw := ""
	if c.Proxy != nil {
		raw = strings.TrimSpace(c.Proxy())
	}
	if raw == "" {
		return tr
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return tr
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		tr.Proxy = http.ProxyURL(u)
	case "socks5", "socks5h":
		d, err := proxy.FromURL(u, proxy.Direct)
		if err != nil {
			return tr
		}
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if cd, ok := d.(proxy.ContextDialer); ok {
				return cd.DialContext(ctx, network, addr)
			}
			return d.Dial(network, addr)
		}
	}
	return tr
}

func (c *Client) httpClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 45 * time.Second
	}
	return &http.Client{Timeout: timeout, Transport: c.transport()}
}

// GetBytes reads a URL into memory, capped at maxBytes.
func (c *Client) GetBytes(ctx context.Context, rawURL string, headers map[string]string, maxBytes int64) ([]byte, http.Header, error) {
	if maxBytes <= 0 {
		maxBytes = 8 << 20
	}
	resp, err := c.do(ctx, rawURL, headers, 45*time.Second)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, resp.Header, err
	}
	if int64(len(body)) > maxBytes {
		return nil, resp.Header, fmt.Errorf("响应超过 %d 字节", maxBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snip := string(body)
		if len(snip) > 180 {
			snip = snip[:180]
		}
		return nil, resp.Header, fmt.Errorf("HTTP %d %s", resp.StatusCode, strings.TrimSpace(snip))
	}
	return body, resp.Header, nil
}

// Download writes a URL to dest and fails when the body exceeds maxBytes.
func (c *Client) Download(ctx context.Context, rawURL, dest string, maxBytes int64) error {
	if maxBytes <= 0 {
		maxBytes = 150 << 20
	}
	resp, err := c.do(ctx, rawURL, nil, 5*time.Minute)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	n, err := io.Copy(f, io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return err
	}
	if n > maxBytes {
		return fmt.Errorf("文件超过 %d 字节", maxBytes)
	}
	return nil
}

func (c *Client) do(ctx context.Context, rawURL string, headers map[string]string, timeout time.Duration) (*http.Response, error) {
	if err := c.wait(ctx); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json, application/xml, text/xml, text/html, */*")
	for k, v := range headers {
		if strings.TrimSpace(v) != "" {
			req.Header.Set(k, v)
		}
	}
	return c.httpClient(timeout).Do(req)
}
