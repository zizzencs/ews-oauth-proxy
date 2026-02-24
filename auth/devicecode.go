package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type DeviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
	Message         string `json:"message"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Error        string `json:"error"`
}

// InitiateDeviceCodeFlow begins the OAuth flow and returns the prompt the user must act on.
func InitiateDeviceCodeFlow(tenantID, clientID, clientSecret, deviceCodeURL, scope string) (*DeviceCodeResponse, error) {
	endpoint := strings.Replace(deviceCodeURL, "%s", tenantID, 1)

	data := url.Values{}
	data.Set("client_id", clientID)
	if clientSecret != "" {
		data.Set("client_secret", clientSecret)
	}
	data.Set("scope", scope)

	req, err := http.NewRequest("POST", endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("auth error (status %d): %s", resp.StatusCode, string(body))
	}

	var dcr DeviceCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&dcr); err != nil {
		return nil, err
	}

	return &dcr, nil
}

// PollForToken blocks and polls the token endpoint until the user completes the device login.
func PollForToken(tenantID, clientID, clientSecret, tokenURL, deviceCode string, interval int) (*TokenResponse, error) {
	fmt.Println("Waiting for authentication... (polling every", interval, "seconds)")

	endpoint := strings.Replace(tokenURL, "%s", tenantID, 1)
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	client := &http.Client{Timeout: 10 * time.Second}

	for {
		<-ticker.C

		data := url.Values{}
		data.Set("client_id", clientID)
		if clientSecret != "" {
			data.Set("client_secret", clientSecret)
		}
		data.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
		data.Set("device_code", deviceCode)

		req, err := http.NewRequest("POST", endpoint, strings.NewReader(data.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		resp, err := client.Do(req)
		if err != nil {
			continue // network error, try again next tick
		}

		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var tr TokenResponse
		json.Unmarshal(bodyBytes, &tr)

		if tr.Error == "authorization_pending" {
			// User hasn't logged in yet, keep waiting
			continue
		}

		if tr.Error != "" {
			return nil, fmt.Errorf("polling error: %s", tr.Error)
		}

		if tr.AccessToken != "" {
			return &tr, nil
		}
	}
}
