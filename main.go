package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"ews-oauth-proxy/auth"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
)

type Config struct {
	TenantID      string
	ClientID      string
	ClientSecret  string
	ListenAddress string
	TokenFile     string
	CertFile      string
	KeyFile       string
	TargetURL     string
	DeviceCodeURL string
	TokenURL      string
	Scope         string
	Username      string
	Password      string
}

func loadEnvFile(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		return
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])

			// Strip surrounding quotes if present
			if (strings.HasPrefix(val, "\"") && strings.HasSuffix(val, "\"")) || (strings.HasPrefix(val, "'") && strings.HasSuffix(val, "'")) {
				val = val[1 : len(val)-1]
			}

			if _, exists := os.LookupEnv(key); !exists {
				os.Setenv(key, val)
			}
		}
	}
}

func loadConfig() (*Config, error) {
	configFile := os.Getenv("EWS_OAUTH_PROXY_CONFIG")
	if configFile == "" {
		configFile = "config.env"
	}
	loadEnvFile(configFile)

	tenantID := os.Getenv("EWS_OAUTH_PROXY_TENANT_ID")
	clientID := os.Getenv("EWS_OAUTH_PROXY_CLIENT_ID")
	clientSecret := os.Getenv("EWS_OAUTH_PROXY_CLIENT_SECRET")
	listenAddress := os.Getenv("EWS_OAUTH_PROXY_LISTEN_ADDRESS")
	tokenFile := os.Getenv("EWS_OAUTH_PROXY_TOKEN_FILE")
	certFile := os.Getenv("EWS_OAUTH_PROXY_CERT_FILE")
	keyFile := os.Getenv("EWS_OAUTH_PROXY_KEY_FILE")
	targetURL := os.Getenv("EWS_OAUTH_PROXY_TARGET_URL")
	deviceCodeURL := os.Getenv("EWS_OAUTH_PROXY_DEVICE_CODE_URL")
	tokenURL := os.Getenv("EWS_OAUTH_PROXY_TOKEN_URL")
	scope := os.Getenv("EWS_OAUTH_PROXY_SCOPE")
	username := os.Getenv("EWS_OAUTH_PROXY_USERNAME")
	password := os.Getenv("EWS_OAUTH_PROXY_PASSWORD")

	if tenantID == "" {
		tenantID = "common"
	}
	if clientID == "" {
		clientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c" // Default to Outlook desktop application
	}
	// no default for clientSecret
	if listenAddress == "" {
		listenAddress = "127.0.0.1:8443"
	}
	if tokenFile == "" {
		tokenFile = ".token.json"
	}
	if certFile == "" {
		certFile = "certs/cert.pem"
	}
	if keyFile == "" {
		keyFile = "certs/key.pem"
	}
	if targetURL == "" {
		targetURL = "https://outlook.office365.com"
	}
	if deviceCodeURL == "" {
		deviceCodeURL = "https://login.microsoftonline.com/%s/oauth2/v2.0/devicecode"
	}
	if tokenURL == "" {
		tokenURL = "https://login.microsoftonline.com/%s/oauth2/v2.0/token"
	}
	if scope == "" {
		scope = "https://outlook.office365.com/EWS.AccessAsUser.All offline_access"
	}

	return &Config{
		TenantID:      tenantID,
		ClientID:      clientID,
		ClientSecret:  clientSecret,
		ListenAddress: listenAddress,
		TokenFile:     tokenFile,
		CertFile:      certFile,
		KeyFile:       keyFile,
		TargetURL:     targetURL,
		DeviceCodeURL: deviceCodeURL,
		TokenURL:      tokenURL,
		Scope:         scope,
		Username:      username,
		Password:      password,
	}, nil
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize the Token Manager
	tm := auth.NewTokenManager(cfg.TenantID, cfg.ClientID, cfg.ClientSecret, cfg.TokenFile, cfg.DeviceCodeURL, cfg.TokenURL, cfg.Scope)
	if err := tm.Start(); err != nil {
		log.Fatalf("Authentication failed: %v", err)
	}

	targetURL, _ := url.Parse(cfg.TargetURL)

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = targetURL.Scheme
			req.URL.Host = targetURL.Host
			req.Host = targetURL.Host

			// Strip Basic Auth added by the mail client
			req.Header.Del("Authorization")

			// Inject Bearer Token
			req.Header.Set("Authorization", "Bearer "+tm.GetToken())
		},

		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if errors.Is(err, context.Canceled) {
				log.Printf("[PROXY] Client cancelled request: %v", err)
				w.WriteHeader(499) // Client Closed Request
				return
			}
			log.Printf("[PROXY] Proxy error: %v", err)
			w.WriteHeader(http.StatusBadGateway)
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if cfg.Username != "" && cfg.Password != "" {
			reqUser, reqPass, ok := r.BasicAuth()
			if !ok || reqUser != cfg.Username || reqPass != cfg.Password {
				w.Header().Set("WWW-Authenticate", `Basic realm="ews-oauth-proxy"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}

		proxy.ServeHTTP(w, r)
	})

	serverAddr := cfg.ListenAddress

	displayAddr := serverAddr
	suffix := ""
	if strings.HasPrefix(displayAddr, "0.0.0.0:") {
		displayAddr = strings.Replace(displayAddr, "0.0.0.0:", "127.0.0.1:", 1)
		suffix = " (or your server's IP address)"
	} else if strings.HasPrefix(displayAddr, ":") {
		displayAddr = "127.0.0.1" + displayAddr
		suffix = " (or your server's IP address)"
	}

	log.Printf("ews-oauth-proxy starting on https://%s", serverAddr)
	log.Printf("Point your mail client's Exchange Server URL to: https://%s/EWS/Exchange.asmx%s", displayAddr, suffix)

	if err := http.ListenAndServeTLS(serverAddr, cfg.CertFile, cfg.KeyFile, mux); err != nil {
		log.Fatalf("Server failed to start TLS: %v", err)
	}
}
