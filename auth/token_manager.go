package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// AuthFlow selects how an initial refresh token is obtained.
type AuthFlow string

const (
	FlowDeviceCode   AuthFlow = "device"
	FlowAuthCodePKCE AuthFlow = "interactive"
)

type TokenManager struct {
	tenantID      string
	clientID      string
	clientSecret  string
	tokenFile     string
	deviceCodeURL string
	authorizeURL  string
	tokenURL      string
	redirectURI   string
	scope         string
	authFlow      AuthFlow
	mu            sync.RWMutex
	accessToken   string
	refreshToken  string
	expiresAt     time.Time
}

func NewTokenManager(tenantID, clientID, clientSecret, tokenFile, deviceCodeURL, authorizeURL, tokenURL, redirectURI, scope string, authFlow AuthFlow) *TokenManager {
	if tokenFile == "" {
		tokenFile = ".token.json"
	}
	if authFlow == "" {
		authFlow = FlowDeviceCode
	}
	return &TokenManager{
		tenantID:      tenantID,
		clientID:      clientID,
		clientSecret:  clientSecret,
		tokenFile:     tokenFile,
		deviceCodeURL: deviceCodeURL,
		authorizeURL:  authorizeURL,
		tokenURL:      tokenURL,
		redirectURI:   redirectURI,
		scope:         scope,
		authFlow:      authFlow,
	}
}

// Start loads the token from disk or initiates a new device code flow if one doesn't exist
func (tm *TokenManager) Start() error {
	log.Println("[AUTH] Initializing Token Manager...")

	if err := tm.loadFromDisk(); err != nil || tm.refreshToken == "" {
		log.Printf("[AUTH] No valid refresh token found. Starting new %s flow.", tm.authFlow)
		if err := tm.runInitialFlow(); err != nil {
			return err
		}
	} else {
		log.Println("[AUTH] Loaded existing refresh token from disk.")
	}

	// Do initial refresh to ensure our Access Token is hot
	if err := tm.doRefresh(); err != nil {
		log.Printf("[AUTH] Failed to refresh existing token: %v. The token may be revoked or expired. Starting new %s flow.", err, tm.authFlow)

		// Unload invalid state
		tm.mu.Lock()
		tm.refreshToken = ""
		tm.accessToken = ""
		tm.mu.Unlock()

		// Attempt a fresh authentication
		if err := tm.runInitialFlow(); err != nil {
			return err
		}
	}

	// Start background refresh routine
	go tm.refreshLoop()

	return nil
}

// GetToken returns the current access token in a thread-safe manner
func (tm *TokenManager) GetToken() string {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.accessToken
}

// runInitialFlow dispatches to the configured initial-authentication flow.
func (tm *TokenManager) runInitialFlow() error {
	var tr *TokenResponse
	var err error

	switch tm.authFlow {
	case FlowAuthCodePKCE:
		tr, err = RunAuthCodeFlow(tm.tenantID, tm.clientID, tm.clientSecret, tm.authorizeURL, tm.tokenURL, tm.redirectURI, tm.scope)
	case FlowDeviceCode, "":
		tr, err = tm.runDeviceFlow()
	default:
		return fmt.Errorf("unknown auth flow: %q", tm.authFlow)
	}
	if err != nil {
		return err
	}

	tm.mu.Lock()
	tm.accessToken = tr.AccessToken
	tm.refreshToken = tr.RefreshToken
	tm.expiresAt = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	tm.mu.Unlock()

	log.Println("[AUTH] Successfully authenticated! Saving token for future use.")
	tm.saveToDisk()
	return nil
}

func (tm *TokenManager) runDeviceFlow() (*TokenResponse, error) {
	dcr, err := InitiateDeviceCodeFlow(tm.tenantID, tm.clientID, tm.clientSecret, tm.deviceCodeURL, tm.scope)
	if err != nil {
		return nil, err
	}

	fmt.Printf("\n=======================================================\n")
	fmt.Printf("ACTION REQUIRED: Microsoft Authentication\n")
	fmt.Printf("%s\n", dcr.Message)
	fmt.Printf("=======================================================\n\n")

	return PollForToken(tm.tenantID, tm.clientID, tm.clientSecret, tm.tokenURL, dcr.DeviceCode, dcr.Interval)
}

func (tm *TokenManager) doRefresh() error {
	endpoint := strings.Replace(tm.tokenURL, "%s", tm.tenantID, 1)

	tm.mu.RLock()
	rt := tm.refreshToken
	tm.mu.RUnlock()

	data := url.Values{}
	data.Set("client_id", tm.clientID)
	if tm.clientSecret != "" {
		data.Set("client_secret", tm.clientSecret)
	}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", rt)

	req, err := http.NewRequest("POST", endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("refresh failed (status %d): %s", resp.StatusCode, string(body))
	}

	var tr TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return err
	}

	tm.mu.Lock()
	tm.accessToken = tr.AccessToken
	if tr.RefreshToken != "" {
		tm.refreshToken = tr.RefreshToken
	}
	tm.expiresAt = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	tm.mu.Unlock()

	tm.saveToDisk()
	log.Printf("[AUTH] Token refreshed successfully. Next refresh around %v", tm.expiresAt.Add(-5*time.Minute))
	return nil
}

func (tm *TokenManager) refreshLoop() {
	for {
		tm.mu.RLock()
		expiresAt := tm.expiresAt
		tm.mu.RUnlock()

		// Refresh 5 minutes before expiration
		refreshTime := expiresAt.Add(-5 * time.Minute)
		sleepDuration := time.Until(refreshTime)

		if sleepDuration <= 0 {
			// Token is already expired or about to expire immediately, refresh now
			log.Println("[AUTH] Token expiration is imminent, refreshing now...")
			if err := tm.doRefresh(); err != nil {
				log.Printf("[AUTH] Background refresh error: %v. Retrying in 1 minute.", err)
				time.Sleep(1 * time.Minute)
				continue
			}
		} else {
			log.Printf("[AUTH] Sleeping %v until next automated token refresh.", sleepDuration)
			time.Sleep(sleepDuration)
			if err := tm.doRefresh(); err != nil {
				log.Printf("[AUTH] Background refresh error: %v. Retrying in 1 minute.", err)
				time.Sleep(1 * time.Minute)
				continue
			}
		}
	}
}

func (tm *TokenManager) saveToDisk() error {
	tm.mu.RLock()
	data := map[string]string{
		"refresh_token": tm.refreshToken,
	}
	tm.mu.RUnlock()

	fileBytes, _ := json.MarshalIndent(data, "", "  ")
	// Use 0600 so only the user can read the token file
	return os.WriteFile(tm.tokenFile, fileBytes, 0600)
}

func (tm *TokenManager) loadFromDisk() error {
	fileBytes, err := os.ReadFile(tm.tokenFile)
	if err != nil {
		return err
	}

	var data map[string]string
	if err := json.Unmarshal(fileBytes, &data); err != nil {
		return err
	}

	tm.mu.Lock()
	tm.refreshToken = data["refresh_token"]
	tm.mu.Unlock()

	return nil
}
