package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Client wraps HTTP calls to the sandbox API.
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	token      string
}

const rhProxyHost = "squid.redhat.com"
const rhProxyPort = "3128"

var rhProxyNotified bool

// newHTTPClient creates an http.Client with proxy support.
//
// Proxy resolution order:
//  1. Standard HTTP_PROXY / HTTPS_PROXY / NO_PROXY env vars (if set)
//  2. Auto-detect Red Hat VPN (squid.redhat.com:3128) when DNS resolves
//  3. Direct connection (no proxy)
//
// To force direct access, set NO_PROXY=* or HTTPS_PROXY= (empty).
func newHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()

	if hasProxyEnv() {
		// Standard env vars are set — let Go handle them as usual.
		transport.Proxy = http.ProxyFromEnvironment
	} else if proxyURL := detectRHProxy(); proxyURL != nil {
		proxy := http.ProxyURL(proxyURL)
		transport.Proxy = func(req *http.Request) (*url.URL, error) {
			if isLoopback(req.URL.Hostname()) {
				return nil, nil
			}
			return proxy(req)
		}
		if !rhProxyNotified {
			rhProxyNotified = true
			fmt.Fprintln(os.Stderr, "Using Red Hat VPN proxy (squid.redhat.com:3128)")
		}
	}

	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}
}

// hasProxyEnv returns true if any standard proxy env var is set (even if empty,
// which means "direct connection").
func hasProxyEnv() bool {
	for _, key := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy"} {
		if _, ok := os.LookupEnv(key); ok {
			return true
		}
	}
	return false
}

// isLoopback returns true if the host is a loopback address (127.0.0.0/8,
// ::1, or "localhost"). These should never be proxied.
func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// detectRHProxy checks if squid.redhat.com resolves (indicating the RH VPN is
// active) and returns the proxy URL. Returns nil if not on VPN.
func detectRHProxy() *url.URL {
	_, err := net.LookupHost(rhProxyHost)
	if err != nil {
		return nil
	}
	u, _ := url.Parse("http://" + rhProxyHost + ":" + rhProxyPort)
	return u
}

// NewClient creates a client with the given base URL and access token.
func NewClient(baseURL, accessToken string) *Client {
	return &Client{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		HTTPClient: newHTTPClient(),
		token:      accessToken,
	}
}

// do executes an HTTP request and returns the response.
func (c *Client) do(method, path string, body io.Reader) (*http.Response, error) {
	url := c.BaseURL + path
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	return c.HTTPClient.Do(req)
}

// LoginResponse is the response from GET /api/v1/login.
type LoginResponse struct {
	AccessToken    string     `json:"access_token"`
	AccessTokenExp *time.Time `json:"access_token_exp"`
}

// Login exchanges a login token for an access token.
func Login(baseURL, loginToken string) (*LoginResponse, error) {
	url := strings.TrimRight(baseURL, "/") + "/api/v1/login"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+loginToken)

	client := newHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("login failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var loginResp LoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		return nil, fmt.Errorf("parsing login response: %w", err)
	}
	return &loginResp, nil
}

// Get performs a GET request and returns the raw response.
func (c *Client) Get(path string) (*http.Response, error) {
	return c.do("GET", path, nil)
}

// Post performs a POST request with a JSON body.
func (c *Client) Post(path string, body io.Reader) (*http.Response, error) {
	return c.do("POST", path, body)
}

// Put performs a PUT request with an optional JSON body.
func (c *Client) Put(path string, body io.Reader) (*http.Response, error) {
	return c.do("PUT", path, body)
}

// Delete performs a DELETE request.
func (c *Client) Delete(path string) (*http.Response, error) {
	return c.do("DELETE", path, nil)
}

// ReadJSON reads the response body and decodes it into v.
// It also closes the body. Returns an error with the body text on non-2xx status.
func ReadJSON(resp *http.Response, v any) error {
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

// ReadError reads the response body and returns it as an error string.
// It also closes the body.
func ReadError(resp *http.Response) error {
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
}
