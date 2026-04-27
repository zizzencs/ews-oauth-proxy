package auth

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// generatePKCE returns a random verifier and its S256-derived challenge.
func generatePKCE() (verifier, challenge string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(buf)

	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}

// buildAuthorizeURL constructs the OAuth authorize URL the user must open in a browser.
func buildAuthorizeURL(authorizeURL, tenantID, clientID, redirectURI, scope, challenge, state string) string {
	endpoint := strings.Replace(authorizeURL, "%s", tenantID, 1)

	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", redirectURI)
	q.Set("response_mode", "query")
	q.Set("scope", scope)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", state)
	q.Set("prompt", "select_account")

	return endpoint + "?" + q.Encode()
}

// extractCode pulls the authorization code out of either a full redirected URL
// (e.g. "https://login.microsoftonline.com/common/oauth2/nativeclient?code=...&state=...")
// or a bare code string pasted by the user.
func extractCode(input string) (string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", fmt.Errorf("empty input")
	}

	// If it parses as a URL with a "code" query parameter, use that.
	if strings.Contains(input, "?") || strings.HasPrefix(input, "http") {
		u, err := url.Parse(input)
		if err == nil {
			if c := u.Query().Get("code"); c != "" {
				return c, nil
			}
			if errQ := u.Query().Get("error"); errQ != "" {
				return "", fmt.Errorf("authorization error: %s — %s", errQ, u.Query().Get("error_description"))
			}
		}
	}

	// Otherwise treat the whole input as the code itself.
	return input, nil
}

// RunAuthCodeFlow performs the browser-based OAuth authorization code flow with PKCE.
// It prints the authorize URL, waits for the user to paste the redirected URL or
// authorization code, then exchanges it for an access + refresh token pair.
func RunAuthCodeFlow(tenantID, clientID, clientSecret, authorizeURL, tokenURL, redirectURI, scope string) (*TokenResponse, error) {
	verifier, challenge, err := generatePKCE()
	if err != nil {
		return nil, fmt.Errorf("failed to generate PKCE: %w", err)
	}

	stateBuf := make([]byte, 12)
	if _, err := rand.Read(stateBuf); err != nil {
		return nil, err
	}
	state := base64.RawURLEncoding.EncodeToString(stateBuf)

	authURL := buildAuthorizeURL(authorizeURL, tenantID, clientID, redirectURI, scope, challenge, state)

	fmt.Printf("\n=======================================================\n")
	fmt.Printf("ACTION REQUIRED: Microsoft Authentication (Interactive)\n")
	fmt.Printf("=======================================================\n\n")
	fmt.Printf("1. Open this URL in your browser:\n\n%s\n\n", authURL)
	fmt.Printf("2. Sign in. Your browser will be redirected to a near-blank\n")
	fmt.Printf("   page on %s.\n", redirectURI)
	fmt.Printf("3. Copy the FULL URL from your browser's address bar (or just\n")
	fmt.Printf("   the value of the `code` parameter) and paste it below.\n\n")
	fmt.Printf("Paste here: ")

	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read pasted code: %w", err)
	}

	code, err := extractCode(line)
	if err != nil {
		return nil, err
	}

	// Exchange the code for tokens.
	endpoint := strings.Replace(tokenURL, "%s", tenantID, 1)

	data := url.Values{}
	data.Set("client_id", clientID)
	if clientSecret != "" {
		data.Set("client_secret", clientSecret)
	}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("code_verifier", verifier)
	data.Set("scope", scope)

	req, err := http.NewRequest("POST", endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token exchange failed (status %d): %s", resp.StatusCode, string(body))
	}

	var tr TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, err
	}
	if tr.AccessToken == "" {
		return nil, fmt.Errorf("token exchange returned no access token")
	}

	return &tr, nil
}
