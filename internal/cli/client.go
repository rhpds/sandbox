package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client wraps HTTP calls to the sandbox API.
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	token      string
}

// NewClient creates a client with the given base URL and access token.
func NewClient(baseURL, accessToken string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		token: accessToken,
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

	client := &http.Client{Timeout: 30 * time.Second}
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
