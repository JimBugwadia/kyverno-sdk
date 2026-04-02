package http

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultBlockedCIDRs is the default set of CIDR ranges blocked to prevent SSRF attacks.
// It covers loopback, link-local (cloud metadata), RFC-1918 private, and shared address space.
var DefaultBlockedCIDRs = []string{
	"127.0.0.0/8",    // loopback
	"::1/128",        // IPv6 loopback
	"169.254.0.0/16", // link-local — covers AWS (169.254.169.254), GCP, Azure, DO, Alibaba metadata IPs
	"fe80::/10",      // IPv6 link-local
	"10.0.0.0/8",     // RFC-1918 private
	"172.16.0.0/12",  // RFC-1918 private
	"192.168.0.0/16", // RFC-1918 private
	"fc00::/7",       // IPv6 unique local address (ULA)
	"100.64.0.0/10",  // shared address space (RFC 6598, used by some cloud NAT/VPCs)
}

// DefaultBlockedHosts is the default set of hostnames blocked to prevent SSRF attacks.
// These are cloud provider metadata endpoints whose IPs may not always fall in DefaultBlockedCIDRs.
var DefaultBlockedHosts = []string{
	"metadata.google.internal", // GCP metadata server
	"metadata.internal",        // Oracle Cloud metadata server
}

// ClientInterface is the interface for making HTTP requests.
type ClientInterface interface {
	Do(*http.Request) (*http.Response, error)
}

type contextImpl struct {
	client             ClientInterface
	blockedCIDRs       []*net.IPNet
	blockedHosts       map[string]struct{}
	allowedURLPrefixes []*url.URL
}

// NewHTTP creates a ContextInterface with no URL restrictions. Intended for testing and internal use.
// For production admission controllers use NewHTTPWithDefaultBlocklist or NewHTTPWithBlocklist.
func NewHTTP(client ClientInterface) ContextInterface {
	if client == nil {
		client = http.DefaultClient
	}
	return &contextImpl{client: client}
}

// NewHTTPWithDefaultBlocklist creates a ContextInterface with the default SSRF blocklist applied.
// It panics if the default blocklist contains an invalid entry, which indicates a programming error.
func NewHTTPWithDefaultBlocklist(client ClientInterface) ContextInterface {
	ctx, err := NewHTTPWithBlocklist(client, append(DefaultBlockedCIDRs, DefaultBlockedHosts...), nil)
	if err != nil {
		panic(fmt.Sprintf("kyverno.http: default blocklist is invalid: %v", err))
	}
	return ctx
}

// NewHTTPWithBlocklist creates a ContextInterface with configurable URL validation.
//
// blocklist entries may be:
//   - CIDR ranges (e.g. "10.0.0.0/8"): the resolved IP of any requested host is checked against these.
//   - Hostnames (e.g. "metadata.google.internal"): matched against the exact request hostname.
//
// allowlist entries are URL prefixes (scheme + host, optionally + path prefix).
// When the allowlist is non-empty, a request URL must match at least one entry — scheme and host
// must be identical and the request path must start with the entry's path. The blocklist is
// still enforced on top of the allowlist for defence in depth.
func NewHTTPWithBlocklist(client ClientInterface, blocklist, allowlist []string) (ContextInterface, error) {
	if client == nil {
		client = http.DefaultClient
	}

	var blockedCIDRs []*net.IPNet
	blockedHosts := make(map[string]struct{})
	for _, entry := range blocklist {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			_, ipNet, err := net.ParseCIDR(entry)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q in blocklist: %w", entry, err)
			}
			blockedCIDRs = append(blockedCIDRs, ipNet)
		} else {
			blockedHosts[entry] = struct{}{}
		}
	}

	var allowedURLPrefixes []*url.URL
	for _, entry := range allowlist {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		u, err := url.Parse(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid allowlist URL %q: %w", entry, err)
		}
		if u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("allowlist entry %q must include scheme and host (e.g. https://api.example.com)", entry)
		}
		allowedURLPrefixes = append(allowedURLPrefixes, u)
	}

	return &contextImpl{
		client:             client,
		blockedCIDRs:       blockedCIDRs,
		blockedHosts:       blockedHosts,
		allowedURLPrefixes: allowedURLPrefixes,
	}, nil
}

func (r *contextImpl) validateURL(rawURL string) error {
	if len(r.blockedCIDRs) == 0 && len(r.blockedHosts) == 0 && len(r.allowedURLPrefixes) == 0 {
		return nil
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	host := u.Hostname()

	// Allowlist check: if configured, the URL must match at least one entry.
	if len(r.allowedURLPrefixes) > 0 {
		if !r.matchesAllowlist(u) {
			return fmt.Errorf("URL %q is not permitted: no matching allowlist entry", rawURL)
		}
	}

	// Hostname blocklist check.
	if _, blocked := r.blockedHosts[host]; blocked {
		return fmt.Errorf("URL %q is blocked: hostname %q is on the blocklist", rawURL, host)
	}

	// IP/CIDR blocklist check.
	if len(r.blockedCIDRs) > 0 {
		if ip := net.ParseIP(host); ip != nil {
			// Host is a literal IP address.
			if err := r.checkIP(ip, rawURL); err != nil {
				return err
			}
		} else {
			// Resolve the hostname and check each resulting IP.
			resolveCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			addrs, err := net.DefaultResolver.LookupHost(resolveCtx, host)
			if err != nil {
				return fmt.Errorf("URL %q is blocked: hostname resolution failed: %w", rawURL, err)
			}
			for _, addr := range addrs {
				ip := net.ParseIP(addr)
				if ip == nil {
					continue
				}
				if err := r.checkIP(ip, rawURL); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (r *contextImpl) matchesAllowlist(reqURL *url.URL) bool {
	for _, entry := range r.allowedURLPrefixes {
		if reqURL.Scheme != entry.Scheme || reqURL.Host != entry.Host {
			continue
		}
		entryPath := entry.Path
		if entryPath == "" || entryPath == "/" {
			return true
		}
		if strings.HasPrefix(reqURL.Path, entryPath) {
			return true
		}
	}
	return false
}

func (r *contextImpl) checkIP(ip net.IP, rawURL string) error {
	for _, cidr := range r.blockedCIDRs {
		if cidr.Contains(ip) {
			return fmt.Errorf("URL %q is blocked: resolved IP %s falls in blocked range %s", rawURL, ip, cidr)
		}
	}
	return nil
}

func (r *contextImpl) Get(url string, headers map[string]string) (any, error) {
	if err := r.validateURL(url); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(context.TODO(), "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	for h, v := range headers {
		req.Header.Add(h, v)
	}
	return r.executeRequest(r.client, req)
}

func (r *contextImpl) Post(url string, data any, headers map[string]string) (any, error) {
	if err := r.validateURL(url); err != nil {
		return nil, err
	}
	body, err := buildRequestData(data)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request data: %w", err)
	}
	req, err := http.NewRequestWithContext(context.TODO(), "POST", url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	for h, v := range headers {
		req.Header.Add(h, v)
	}
	return r.executeRequest(r.client, req)
}

func (r *contextImpl) executeRequest(client ClientInterface, req *http.Request) (any, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var body any
	if resp.Body != nil {
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			body = nil
		}
	}

	if bodyMap, ok := body.(map[string]any); ok {
		bodyMap["statusCode"] = resp.StatusCode
		return bodyMap, nil
	}

	return map[string]any{
		"body":       body,
		"statusCode": resp.StatusCode,
	}, nil
}

func (r *contextImpl) Client(caBundle string) (ContextInterface, error) {
	if caBundle == "" {
		return r, nil
	}
	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM([]byte(caBundle)); !ok {
		return nil, fmt.Errorf("failed to parse PEM CA bundle for APICall")
	}
	return &contextImpl{
		client: &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    caCertPool,
				MinVersion: tls.VersionTLS12,
			},
		}},
		blockedCIDRs:       r.blockedCIDRs,
		blockedHosts:       r.blockedHosts,
		allowedURLPrefixes: r.allowedURLPrefixes,
	}, nil
}

func buildRequestData(data any) (io.Reader, error) {
	buffer := new(bytes.Buffer)
	if err := json.NewEncoder(buffer).Encode(data); err != nil {
		return nil, fmt.Errorf("failed to encode HTTP POST data %v: %w", data, err)
	}
	return buffer, nil
}
