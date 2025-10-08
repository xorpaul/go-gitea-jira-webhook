package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/BurntSushi/toml" // Import the TOML library
)

//go:embed go-gitea-jira-webhook.jpg
var embeddedImage embed.FS

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Build version variables - set via ldflags during build
var (
	buildtime    = "unknown"
	buildversion = "unknown"
)

// Default configuration file path
const defaultConfigPath = "/etc/go-gitea-jira-webhook/config.toml"

// Default token cache file path
var defaultTokenCachePath = func() string {
	homeDir, err := os.UserHomeDir()
	if err != nil || homeDir == "" {
		// Fallback to current directory if home cannot be determined
		return "go-gitea-jira-webhook-token.cache"
	}
	return homeDir + "/.go-gitea-jira-webhook-token.cache"
}()

// Config represents the structure of our TOML configuration file
type Config struct {
	Jira struct {
		APIURL            string   `toml:"api_url"`
		Username          string   `toml:"username"`
		Password          string   `toml:"password"`
		ProjectsFilter    []string `toml:"projects_filter"`    // Optional: only process tickets from these projects
		CommentVisibility string   `toml:"comment_visibility"` // Optional: e.g. "role:Members" or empty for none
	} `toml:"jira"`
	Buffering struct {
		Duration string `toml:"duration"` // Optional: buffer duration like "10m", "5s", etc. - if set, buffering is enabled
	} `toml:"buffering"`
	Gitea struct {
		WebhookSecret string `toml:"webhook_secret"` // Optional
	} `toml:"gitea"`
	SSL struct {
		CertFile string `toml:"cert_file"`
		KeyFile  string `toml:"key_file"`
	} `toml:"ssl"`
	Server struct {
		Port         string   `toml:"port"`          // Can also be hardcoded to 8443
		AllowedCIDRs []string `toml:"allowed_cidrs"` // Optional: allowed IP ranges for POST requests (e.g., ["192.168.1.0/24", "10.0.0.0/8"])
	} `toml:"server"`
}

// JiraAPIToken represents the response from Jira API token creation
type JiraAPIToken struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	CreatedAt  string `json:"createdAt"`
	ExpiringAt string `json:"expiringAt"`
	RawToken   string `json:"rawToken"`
}

// CachedToken represents a cached API token with metadata
type CachedToken struct {
	Token      string `json:"token"`
	CreatedAt  string `json:"created_at"`
	ExpiryDate string `json:"expiry_date"`
	Username   string `json:"username"`
	APIURL     string `json:"api_url"`
}

// CommitInfo represents information about a single commit for bundling
type CommitInfo struct {
	ID        string
	Message   string
	URL       string
	ShortID   string
	Timestamp string // ISO 8601 timestamp from Gitea
	Author    struct {
		Name     string
		Email    string
		Username string
	}
}

// TicketCommits represents all commits associated with a specific Jira ticket
type TicketCommits struct {
	TicketID    string
	Commits     []CommitInfo
	RepoURL     string
	RepoName    string
	ForcePublic bool // True if any commit used $TICKETID format to force public visibility
}

// BufferedTicket represents a ticket with buffered commits and timer
type BufferedTicket struct {
	TicketData *TicketCommits
	Timer      *time.Timer
	FirstSeen  time.Time
}

// Global variables to hold configuration and compiled regex
var (
	appConfig       Config
	jiraAPIToken    string // Store the generated API token
	jiraTicketRegex *regexp.Regexp

	// Buffering variables
	bufferMutex     sync.Mutex
	bufferedTickets map[string]*BufferedTicket
	bufferDuration  time.Duration
)

// loadConfiguration loads and validates the configuration from the specified file
func loadConfiguration(configPath string) error {
	// Load configuration from TOML file
	if _, err := toml.DecodeFile(configPath, &appConfig); err != nil {
		return fmt.Errorf("error loading configuration from %s: %v", configPath, err)
	}

	// Validate essential config fields
	if appConfig.Jira.APIURL == "" {
		return fmt.Errorf("Jira.APIURL is not set in the configuration file")
	}
	if appConfig.Jira.Username == "" {
		return fmt.Errorf("Jira.Username is not set in the configuration file")
	}
	if appConfig.Jira.Password == "" {
		return fmt.Errorf("Jira.Password is not set in the configuration file")
	}
	if appConfig.SSL.CertFile == "" {
		return fmt.Errorf("SSL.CertFile is not set in the configuration file")
	}
	if appConfig.SSL.KeyFile == "" {
		return fmt.Errorf("SSL.KeyFile is not set in the configuration file")
	}

	// Get or create Jira API token (with caching and validation)
	log.Println("Getting Jira API token...")
	token, err := getOrCreateJiraToken(appConfig.Jira.Username, appConfig.Jira.Password, appConfig.Jira.APIURL)
	if err != nil {
		return fmt.Errorf("failed to get Jira API token: %w", err)
	}
	jiraAPIToken = token

	// Compile the regex once at startup - captures $TICKETID and #TICKETID (public) and TICKETID (normal) formats
	jiraTicketRegex = regexp.MustCompile(`\b([\$#]?[A-Z]+-[0-9]+)\b`)

	log.Println("Service initialized and configuration loaded.")
	log.Printf("JIRA API URL: %s", appConfig.Jira.APIURL)
	if len(appConfig.Jira.ProjectsFilter) > 0 {
		log.Printf("Jira projects filter enabled: %v", appConfig.Jira.ProjectsFilter)
	} else {
		log.Println("Jira projects filter disabled - processing all projects")
	}
	if appConfig.Gitea.WebhookSecret != "" {
		log.Println("Gitea webhook secret is configured.")
	} else {
		log.Println("WARNING: Gitea webhook secret is NOT configured. Webhook requests will not be verified.")
	}
	if len(appConfig.Server.AllowedCIDRs) > 0 {
		log.Printf("IP restrictions enabled: POST requests allowed only from: %v", appConfig.Server.AllowedCIDRs)
	} else {
		log.Println("WARNING: No IP restrictions configured. POST requests accepted from any IP address.")
	}
	log.Printf("Listening with TLS. Cert File: %s, Key File: %s", appConfig.SSL.CertFile, appConfig.SSL.KeyFile)

	// Initialize buffering if duration is set
	bufferedTickets = make(map[string]*BufferedTicket)
	if appConfig.Buffering.Duration != "" {
		var err error
		bufferDuration, err = time.ParseDuration(appConfig.Buffering.Duration)
		if err != nil {
			return fmt.Errorf("invalid buffering duration '%s': %w", appConfig.Buffering.Duration, err)
		}
		log.Printf("Commit buffering enabled with duration: %s", bufferDuration)
	} else {
		log.Println("Commit buffering disabled - comments will be posted immediately")
	}

	return nil
}

// createJiraAPIToken creates a new Personal Access Token using username and password
func createJiraAPIToken(username, password, apiURL string) (*JiraAPIToken, error) {
	// Create PAT request payload with 90-day expiration
	tokenName := fmt.Sprintf("gitea-webhook-%d", time.Now().Unix())

	payload := map[string]any{
		"name":               tokenName,
		"expirationDuration": 90,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("error marshaling token creation payload: %w", err)
	}

	// Create the PAT creation request using the correct endpoint
	tokenURL := fmt.Sprintf("%s/rest/pat/latest/tokens", apiURL)
	log.Printf("Creating Jira API token with URL: %s", tokenURL)
	req, err := http.NewRequest(http.MethodPost, tokenURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, fmt.Errorf("error creating token request: %w", err)
	}

	req.SetBasicAuth(username, password)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending token creation request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Jira API returned non-success status for token creation: %d - %s", resp.StatusCode, string(respBody))
	}

	var tokenResponse JiraAPIToken
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return nil, fmt.Errorf("error decoding token response: %w", err)
	}

	log.Printf("Successfully created Jira Personal Access Token: %s (expires: %s)", tokenResponse.Name, tokenResponse.ExpiringAt)
	return &tokenResponse, nil
} // saveTokenToCache saves the API token to local filesystem cache
func saveTokenToCache(token, username, apiURL, expiryDate string) error {
	cachedToken := CachedToken{
		Token:      token,
		CreatedAt:  time.Now().Format(time.RFC3339),
		ExpiryDate: expiryDate,
		Username:   username,
		APIURL:     apiURL,
	}

	data, err := json.Marshal(cachedToken)
	if err != nil {
		return fmt.Errorf("error marshaling cached token: %w", err)
	}

	if err := os.WriteFile(defaultTokenCachePath, data, 0600); err != nil {
		return fmt.Errorf("error writing token cache file: %w", err)
	}

	log.Printf("Saved API token to cache: %s", defaultTokenCachePath)
	return nil
}

// loadTokenFromCache loads the API token from local filesystem cache
func loadTokenFromCache(username, apiURL string) (string, error) {
	data, err := os.ReadFile(defaultTokenCachePath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("token cache file does not exist")
		}
		return "", fmt.Errorf("error reading token cache file: %w", err)
	}

	var cachedToken CachedToken
	if err := json.Unmarshal(data, &cachedToken); err != nil {
		return "", fmt.Errorf("error unmarshaling cached token: %w", err)
	}

	// Verify the cached token is for the same username and API URL
	if cachedToken.Username != username || cachedToken.APIURL != apiURL {
		return "", fmt.Errorf("cached token is for different username or API URL")
	}

	log.Printf("Loaded API token from cache (created: %s, expires: %s)", cachedToken.CreatedAt, cachedToken.ExpiryDate)

	// Check if token is near expiration
	if isTokenNearExpiration(cachedToken.ExpiryDate) {
		return "", fmt.Errorf("cached token is near expiration or expired")
	}

	return cachedToken.Token, nil
}

// validateJiraToken tests if the API token is valid by making a simple API call
func validateJiraToken(token, apiURL string) error {
	// Test the token by getting API content info
	testURL := fmt.Sprintf("%s/rest/api/2/mypermissions", apiURL)
	// log.Printf("Validating token with value: %s", token)
	log.Printf("Validating token with URL: %s", testURL)
	req, err := http.NewRequest(http.MethodGet, testURL, nil)
	if err != nil {
		return fmt.Errorf("error creating validation request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending validation request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("token is invalid or expired")
	}

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("validation request failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	// log.Printf("API token validation successful - response %s", string(respBody))
	log.Printf("API token validation successful")
	return nil
}

// isTokenNearExpiration checks if a token will expire within the next 7 days
func isTokenNearExpiration(expiryDateStr string) bool {
	if expiryDateStr == "" {
		log.Printf("Warning: Empty expiry date, considering token as expired")
		return true
	}

	// Parse the expiry date (Jira returns ISO 8601 format like "2024-12-12T16:19:28.000+0100")
	expiryDate, err := time.Parse(time.RFC3339, expiryDateStr)
	if err != nil {
		// Try alternative format without milliseconds
		expiryDate, err = time.Parse("2006-01-02T15:04:05Z07:00", expiryDateStr)
		if err != nil {
			log.Printf("Warning: Unable to parse expiry date '%s': %v, considering token as expired", expiryDateStr, err)
			return true
		}
	}

	// Check if token expires within the next 7 days
	sevenDaysFromNow := time.Now().Add(7 * 24 * time.Hour)
	isNearExpiration := expiryDate.Before(sevenDaysFromNow)

	if isNearExpiration {
		log.Printf("Token expires on %s, which is within 7 days. Renewal required.", expiryDate.Format(time.RFC3339))
	} else {
		log.Printf("Token expires on %s, which is more than 7 days away. No renewal needed.", expiryDate.Format(time.RFC3339))
	}

	return isNearExpiration
}

// getOrCreateJiraToken attempts to load a cached token, validates it, and creates a new one if needed
func getOrCreateJiraToken(username, password, apiURL string) (string, error) {
	// Try to load cached token first
	if cachedToken, err := loadTokenFromCache(username, apiURL); err == nil {
		log.Println("Testing cached API token...")
		if err := validateJiraToken(cachedToken, apiURL); err == nil {
			log.Println("Cached API token is valid, using it")
			return cachedToken, nil
		}
		log.Printf("Cached API token is invalid: %v", err)
	} else {
		log.Printf("No valid cached token found: %v", err)
	}

	// Create new token
	log.Println("Creating new Jira API token...")
	newTokenResponse, err := createJiraAPIToken(username, password, apiURL)
	if err != nil {
		return "", fmt.Errorf("failed to create new API token: %w", err)
	}

	// Validate the new token
	log.Println("Validating new API token...")
	if err := validateJiraToken(newTokenResponse.RawToken, apiURL); err != nil {
		return "", fmt.Errorf("new API token validation failed: %w", err)
	}

	// Save the new token to cache with actual expiry date
	if err := saveTokenToCache(newTokenResponse.RawToken, username, apiURL, newTokenResponse.ExpiringAt); err != nil {
		log.Printf("Warning: failed to save token to cache: %v", err)
	}

	return newTokenResponse.RawToken, nil
}

// refreshJiraToken refreshes the global jiraAPIToken and returns the new token
func refreshJiraToken() error {
	log.Println("Refreshing Jira API token...")
	newToken, err := getOrCreateJiraToken(appConfig.Jira.Username, appConfig.Jira.Password, appConfig.Jira.APIURL)
	if err != nil {
		return fmt.Errorf("failed to refresh Jira API token: %w", err)
	}

	jiraAPIToken = newToken
	log.Println("Jira API token refreshed successfully")
	return nil
}

// startPeriodicTokenRenewal starts a background goroutine that checks for token expiration every hour
func startPeriodicTokenRenewal() {
	go func() {
		log.Println("Starting periodic token renewal checker (every 1 hour)")
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()

		for range ticker.C {
			log.Println("Performing periodic token expiration check...")

			// Try to load the current cached token to check its expiration
			data, err := os.ReadFile(defaultTokenCachePath)
			if err != nil {
				log.Printf("Warning: Could not read token cache for periodic check: %v", err)
				continue
			}

			var cachedToken CachedToken
			if err := json.Unmarshal(data, &cachedToken); err != nil {
				log.Printf("Warning: Could not parse cached token for periodic check: %v", err)
				continue
			}

			// Verify the cached token is for the current configuration
			if cachedToken.Username != appConfig.Jira.Username || cachedToken.APIURL != appConfig.Jira.APIURL {
				log.Printf("Warning: Cached token is for different configuration, skipping periodic check")
				continue
			}

			// Check if token needs renewal
			if isTokenNearExpiration(cachedToken.ExpiryDate) {
				log.Println("Periodic check: Token is near expiration, initiating renewal...")
				if err := refreshJiraToken(); err != nil {
					log.Printf("Error during periodic token renewal: %v", err)
				} else {
					log.Println("Periodic token renewal completed successfully")
				}
			} else {
				log.Println("Periodic check: Token is still valid, no renewal needed")
			}
		}
	}()
}

// GiteaWebhookPayload represents the structure of a Gitea push event webhook
type GiteaWebhookPayload struct {
	Ref        string `json:"ref"`
	Before     string `json:"before"`
	After      string `json:"after"`
	CompareURL string `json:"compare_url"`
	Commits    []struct {
		ID      string `json:"id"`
		Message string `json:"message"`
		URL     string `json:"url"` // This is the Gitea commit web link
		Author  struct {
			Name     string `json:"name"`
			Email    string `json:"email"`
			Username string `json:"username"`
		} `json:"author"`
		Committer struct {
			Name     string `json:"name"`
			Email    string `json:"email"`
			Username string `json:"username"`
		} `json:"committer"`
		Timestamp string `json:"timestamp"`
	} `json:"commits"`
	Repository struct {
		ID       int    `json:"id"`
		Name     string `json:"name"`
		FullName string `json:"full_name"`
		HTMLURL  string `json:"html_url"`
		Owner    struct {
			ID       int    `json:"id"`
			Login    string `json:"login"`
			FullName string `json:"full_name"`
			Email    string `json:"email"`
			HTMLURL  string `json:"html_url"`
		} `json:"owner"`
		Description string `json:"description"`
		Private     bool   `json:"private"`
	} `json:"repository"`
	Pusher struct {
		ID       int    `json:"id"`
		Login    string `json:"login"`
		FullName string `json:"full_name"`
		Email    string `json:"email"`
		HTMLURL  string `json:"html_url"`
	} `json:"pusher"`
	Sender struct {
		ID       int    `json:"id"`
		Login    string `json:"login"`
		FullName string `json:"full_name"`
		Email    string `json:"email"`
		HTMLURL  string `json:"html_url"`
	} `json:"sender"`
}

// verifyGiteaSignature verifies the HMAC signature of the Gitea webhook payload.
func verifyGiteaSignature(payload []byte, secret, signature string) bool {
	if secret == "" {
		return true // No secret configured, so no verification
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expectedMAC := mac.Sum(nil)

	decodedSignature, err := hex.DecodeString(signature)
	if err != nil {
		log.Printf("Error decoding signature: %v", err)
		return false
	}

	return hmac.Equal(decodedSignature, expectedMAC)
}

// isTicketAllowed checks if a Jira ticket is in the allowed projects list
func isTicketAllowed(ticketID string) bool {
	// If no filter is configured, allow all tickets
	if len(appConfig.Jira.ProjectsFilter) == 0 {
		return true
	}

	// Extract project code from ticket ID (e.g., "ITOINFRA-7456" -> "ITOINFRA")
	parts := strings.SplitN(ticketID, "-", 2)
	if len(parts) < 2 {
		log.Printf("Invalid ticket format: %s", ticketID)
		return false
	}

	projectCode := parts[0]

	// Check if project is in the allowed list
	for _, allowedProject := range appConfig.Jira.ProjectsFilter {
		if strings.EqualFold(projectCode, allowedProject) {
			return true
		}
	}

	log.Printf("Ticket %s project '%s' is not in allowed projects filter: %v", ticketID, projectCode, appConfig.Jira.ProjectsFilter)
	return false
}

// isIPAllowed checks if the client IP is in the allowed CIDR ranges
func isIPAllowed(clientIP string, allowedCIDRs []string) bool {
	// If no CIDR restrictions are configured, allow all IPs
	if len(allowedCIDRs) == 0 {
		return true
	}

	// Parse the client IP
	ip := net.ParseIP(clientIP)
	if ip == nil {
		log.Printf("Invalid client IP address: %s", clientIP)
		return false
	}

	// Check if the IP is in any of the allowed CIDR ranges
	for _, cidrStr := range allowedCIDRs {
		_, cidrNet, err := net.ParseCIDR(cidrStr)
		if err != nil {
			log.Printf("Invalid CIDR range in configuration: %s - %v", cidrStr, err)
			continue
		}

		if cidrNet.Contains(ip) {
			return true
		}
	}

	return false
}

// getClientIP extracts the real client IP from the request, considering proxy headers
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (for proxies/load balancers)
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header (some proxies use this)
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr (direct connection)
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// If SplitHostPort fails, RemoteAddr might be just an IP without port
		return r.RemoteAddr
	}
	return host
}

// serviceOverviewHandler handles GET requests to show service configuration overview
func serviceOverviewHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET requests are accepted for overview", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Build overview information
	var bufferStatus string
	if appConfig.Buffering.Duration != "" {
		bufferStatus = fmt.Sprintf("Enabled (%s)", appConfig.Buffering.Duration)
	} else {
		bufferStatus = "Disabled"
	}

	var projectFilter string
	if len(appConfig.Jira.ProjectsFilter) > 0 {
		projectFilter = strings.Join(appConfig.Jira.ProjectsFilter, ", ")
	} else {
		projectFilter = "All projects (no filter)"
	}

	var visibilitySettings string
	if appConfig.Jira.CommentVisibility != "" {
		visibilitySettings = appConfig.Jira.CommentVisibility
	} else {
		visibilitySettings = "Public (no visibility restrictions)"
	}

	var webhookSecurity string
	if appConfig.Gitea.WebhookSecret != "" {
		webhookSecurity = "Enabled (HMAC signature verification)"
	} else {
		webhookSecurity = "Disabled (no signature verification)"
	}

	var ipRestrictions string
	if len(appConfig.Server.AllowedCIDRs) > 0 {
		ipRestrictions = "Enabled (CIDR filtering active)"
	} else {
		ipRestrictions = "Disabled (all IPs allowed)"
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Go Gitea Jira Webhook - Service Overview</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #007acc; padding-bottom: 10px; }
        h2 { color: #555; margin-top: 30px; }
        .status { background: #e8f5e8; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .feature { background: #f0f8ff; padding: 12px; border-left: 4px solid #007acc; margin: 8px 0; }
        .warning { background: #fff3cd; padding: 12px; border-left: 4px solid #ffc107; margin: 8px 0; }
        table { width: 100%%; border-collapse: collapse; margin: 15px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; font-weight: bold; }
        .endpoint { font-family: monospace; background: #f8f9fa; padding: 2px 6px; border-radius: 3px; }
        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 0.9em; }
        .service-image { max-width: 800px; width: 100%%; height: auto; display: block; margin: 20px auto; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔗 Go Gitea Jira Webhook Service</h1>
        
        <img src="/go-gitea-jira-webhook.jpg" alt="Go Gitea Jira Webhook Service" class="service-image">

        <div class="status">
            <strong>Service Status:</strong> Running ✅<br>
            <strong>Build Version:</strong> %s<br>
            <strong>Build Time:</strong> %s
        </div>

        <h2>📋 Configuration Overview</h2>
        <table>
            <tr><th>Setting</th><th>Value</th></tr>
            <tr><td>Jira API URL</td><td>%s</td></tr>
            <tr><td>Jira Username</td><td>%s</td></tr>
            <tr><td>Project Filter</td><td>%s</td></tr>
            <tr><td>Comment Visibility</td><td>%s</td></tr>
            <tr><td>Commit Buffering</td><td>%s</td></tr>
            <tr><td>Webhook Security</td><td>%s</td></tr>
            <tr><td>IP Restrictions</td><td>%s</td></tr>
        </table>

        <h2>🎯 Special Features</h2>
        <div class="feature">
            <strong>💬 Public Comment Override:</strong> Use <code>$TICKETID</code> or <code>#TICKETID</code> format in commit messages (e.g., <code>$PROJ-123</code> or <code>#PROJ-123</code>) to force public visibility, bypassing the comment_visibility setting.
        </div>
        <div class="feature">
            <strong>📦 Commit Bundling:</strong> Multiple commits referencing the same ticket are automatically bundled into a single comment.
        </div>
        <div class="feature">
            <strong>🔄 Token Management:</strong> Automatic Jira API token creation, caching, and renewal with 90-day expiry.
        </div>
        <div class="feature">
            <strong>🛡️ Security:</strong> HTTPS/TLS required, optional HMAC signature verification for webhooks.
        </div>

        <h2>🌐 API Endpoints</h2>
        <table>
            <tr><th>Method</th><th>Endpoint</th><th>Purpose</th></tr>
            <tr><td>GET</td><td class="endpoint">/</td><td>Service overview (this page)</td></tr>
            <tr><td>POST</td><td class="endpoint">/</td><td>Gitea webhook receiver</td></tr>
            <tr><td>POST</td><td class="endpoint">/gitea-webhook</td><td>Gitea webhook receiver (alternative)</td></tr>
            <tr><td>GET</td><td class="endpoint">/go-gitea-jira-webhook.jpg</td><td>Service logo image</td></tr>
        </table>

        <h2>📝 Usage Instructions</h2>
        <div class="feature">
            <strong>Webhook Configuration:</strong> Point your Gitea repository webhook to:<br>
            <code>https://your-server:%s/gitea-webhook</code>
        </div>
        <div class="feature">
            <strong>Commit Message Format:</strong><br>
            • Normal: <code>Fix bug for PROJ-123</code> (uses configured visibility)<br>
            • Public: <code>Fix bug for $PROJ-123</code> or <code>Fix bug for #PROJ-123</code> (forces public visibility)
        </div>

        <div class="footer">
            <p>🚀 <strong>Go Gitea Jira Webhook</strong> - Automatically sync Gitea commits to Jira tickets</p>
            <p>📖 <a href="https://github.com/xorpaul/go-gitea-jira-webhook" target="_blank">Documentation & Source Code</a></p>
        </div>
    </div>
</body>
</html>`, buildversion, buildtime, appConfig.Jira.APIURL, appConfig.Jira.Username, projectFilter, visibilitySettings, bufferStatus, webhookSecurity, ipRestrictions, appConfig.Server.Port)

	fmt.Fprint(w, html)
	log.Printf("Served service overview to %s", r.RemoteAddr)
}

// giteaWebhookHandler handles incoming Gitea webhook POST requests
func giteaWebhookHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received %s request to %s", r.Method, r.URL.Path)
	log.Printf("Headers: %v", r.Header)

	if r.Method != http.MethodPost {
		http.Error(w, "Only POST requests are accepted for webhooks", http.StatusMethodNotAllowed)
		return
	}

	// Check if the client IP is allowed (if CIDR restrictions are configured)
	clientIP := getClientIP(r)
	if !isIPAllowed(clientIP, appConfig.Server.AllowedCIDRs) {
		log.Printf("Webhook request from %s denied - IP not in allowed CIDR ranges: %v", clientIP, appConfig.Server.AllowedCIDRs)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		response := map[string]string{
			"error":   "Forbidden",
			"message": "Your IP address is not authorized to access this webhook endpoint",
			"code":    "IP_NOT_ALLOWED",
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading request body: %v", err)
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	log.Printf("Received webhook payload (first 500 chars): %s", string(body)[:min(500, len(body))])

	giteaSignature := r.Header.Get("X-Gitea-Signature")
	if appConfig.Gitea.WebhookSecret != "" { // Use appConfig.Gitea.WebhookSecret
		if giteaSignature == "" {
			log.Println("Webhook received without X-Gitea-Signature header. Rejecting.")
			http.Error(w, "Missing X-Gitea-Signature header", http.StatusUnauthorized)
			return
		}
		if !verifyGiteaSignature(body, appConfig.Gitea.WebhookSecret, giteaSignature) { // Use appConfig.Gitea.WebhookSecret
			log.Println("Invalid X-Gitea-Signature. Rejecting.")
			http.Error(w, "Invalid X-Gitea-Signature", http.StatusUnauthorized)
			return
		}
		log.Println("Gitea webhook signature verified successfully.")
	} else {
		log.Println("WARNING: Gitea webhook secret not configured, skipping signature verification.")
	}

	eventType := r.Header.Get("X-Gitea-Event")
	if eventType != "push" {
		log.Printf("Received event type '%s', ignoring (only 'push' events are processed).", eventType)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "Event type ignored")
		return
	}

	var payload GiteaWebhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		log.Printf("Error unmarshaling Gitea webhook payload: %v", err)
		http.Error(w, "Error parsing JSON payload", http.StatusBadRequest)
		return
	}

	log.Printf("Received push event for repository: %s (ref: %s)", payload.Repository.FullName, payload.Ref)

	// Collect commits by ticket ID to bundle multiple commits for the same ticket
	ticketCommits := make(map[string]*TicketCommits)

	for _, commit := range payload.Commits {
		commitID := commit.ID
		commitMessage := commit.Message
		commitURL := commit.URL
		commitTimestamp := commit.Timestamp
		repoURL := payload.Repository.HTMLURL
		repoName := payload.Repository.Name

		log.Printf("Processing commit %s: '%s'", commitID[:7], commitMessage)

		foundJiraTickets := jiraTicketRegex.FindAllStringSubmatch(commitMessage, -1)
		if len(foundJiraTickets) > 0 {
			uniqueTickets := make(map[string]bool) // bool indicates if ticket should be public
			for _, match := range foundJiraTickets {
				if len(match) > 1 {
					rawTicketID := match[1]
					var ticketID string
					var forcePublic bool

					// Check if ticket has $ or # prefix for public visibility
					if strings.HasPrefix(rawTicketID, "$") || strings.HasPrefix(rawTicketID, "#") {
						ticketID = rawTicketID[1:] // Remove $ or # prefix
						forcePublic = true
						log.Printf("Found public ticket reference: %s (will bypass visibility settings)", rawTicketID)
					} else {
						ticketID = rawTicketID
						forcePublic = false
					}

					// Check if ticket is in allowed projects
					if isTicketAllowed(ticketID) {
						// If ticket already seen, preserve public flag if any reference was public
						if existing, exists := uniqueTickets[ticketID]; exists {
							uniqueTickets[ticketID] = existing || forcePublic
						} else {
							uniqueTickets[ticketID] = forcePublic
						}
					}
				}
			}

			// Add this commit to each unique ticket it references
			for ticketID, forcePublic := range uniqueTickets {
				if ticketCommits[ticketID] == nil {
					ticketCommits[ticketID] = &TicketCommits{
						TicketID:    ticketID,
						Commits:     []CommitInfo{},
						RepoURL:     repoURL,
						RepoName:    repoName,
						ForcePublic: forcePublic,
					}
				} else {
					// If any reference was public, mark the whole ticket as public
					ticketCommits[ticketID].ForcePublic = ticketCommits[ticketID].ForcePublic || forcePublic
				}

				commitInfo := CommitInfo{
					ID:        commitID,
					Message:   commitMessage,
					URL:       commitURL,
					ShortID:   commitID[:7],
					Timestamp: commitTimestamp,
					Author: struct {
						Name     string
						Email    string
						Username string
					}{
						Name:     commit.Author.Name,
						Email:    commit.Author.Email,
						Username: commit.Author.Username,
					},
				}
				ticketCommits[ticketID].Commits = append(ticketCommits[ticketID].Commits, commitInfo)
				log.Printf("Found Jira ticket '%s' in commit %s. Added to bundle.", ticketID, commitID[:7])
			}
		} else {
			log.Printf("No Jira tickets found in commit %s.", commitID[:7])
		}
	}

	// Process tickets based on buffering configuration
	if appConfig.Buffering.Duration != "" {
		// Add commits to buffer instead of processing immediately
		for ticketID, ticketData := range ticketCommits {
			for _, commit := range ticketData.Commits {
				addCommitToBuffer(ticketID, commit, ticketData.RepoURL, ticketData.RepoName, ticketData.ForcePublic)
			}
		}
	} else {
		// Process each ticket with all its associated commits immediately (legacy behavior)
		for ticketID, ticketData := range ticketCommits {
			log.Printf("Processing ticket %s with %d commit(s)", ticketID, len(ticketData.Commits))
			if err := addCommitLinkToJira(ticketData); err != nil {
				log.Printf("Failed to update Jira ticket %s: %v", ticketID, err)
			} else {
				log.Printf("Successfully updated Jira ticket %s with %d commit(s).", ticketID, len(ticketData.Commits))
			}
		}
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "Webhook processed successfully")
}

// processBufferedTicket processes a buffered ticket by sending the comment to Jira
func processBufferedTicket(ticketID string) {
	bufferMutex.Lock()
	bufferedTicket, exists := bufferedTickets[ticketID]
	if !exists {
		bufferMutex.Unlock()
		return
	}

	// Remove from buffer and stop timer
	delete(bufferedTickets, ticketID)
	if bufferedTicket.Timer != nil {
		bufferedTicket.Timer.Stop()
	}

	ticketData := bufferedTicket.TicketData
	bufferMutex.Unlock()

	log.Printf("Processing buffered ticket %s with %d commit(s) (buffered for %s)",
		ticketID, len(ticketData.Commits), time.Since(bufferedTicket.FirstSeen).Round(time.Second))

	if err := addCommitLinkToJira(ticketData); err != nil {
		log.Printf("Failed to update Jira ticket %s: %v", ticketID, err)
	} else {
		log.Printf("Successfully updated Jira ticket %s with %d commit(s).", ticketID, len(ticketData.Commits))
	}
}

// addCommitToBuffer adds a commit to the buffer for a ticket
func addCommitToBuffer(ticketID string, commitInfo CommitInfo, repoURL, repoName string, forcePublic bool) {
	bufferMutex.Lock()
	defer bufferMutex.Unlock()

	bufferedTicket, exists := bufferedTickets[ticketID]
	if !exists {
		// First commit for this ticket - create new buffer entry
		bufferedTicket = &BufferedTicket{
			TicketData: &TicketCommits{
				TicketID:    ticketID,
				Commits:     []CommitInfo{commitInfo},
				RepoURL:     repoURL,
				RepoName:    repoName,
				ForcePublic: forcePublic,
			},
			FirstSeen: time.Now(),
		}

		// Set timer to process after buffer duration
		bufferedTicket.Timer = time.AfterFunc(bufferDuration, func() {
			processBufferedTicket(ticketID)
		})

		bufferedTickets[ticketID] = bufferedTicket
		log.Printf("Started buffering for ticket %s (will process in %s)", ticketID, bufferDuration)
	} else {
		// Add commit to existing buffer
		bufferedTicket.TicketData.Commits = append(bufferedTicket.TicketData.Commits, commitInfo)
		// If any commit forces public, mark the whole ticket as public
		bufferedTicket.TicketData.ForcePublic = bufferedTicket.TicketData.ForcePublic || forcePublic
		log.Printf("Added commit to buffer for ticket %s (total: %d commits)", ticketID, len(bufferedTicket.TicketData.Commits))
	}
}

// flushAllBufferedTickets processes all remaining buffered tickets immediately
func flushAllBufferedTickets() {
	bufferMutex.Lock()
	ticketIDs := make([]string, 0, len(bufferedTickets))
	for ticketID := range bufferedTickets {
		ticketIDs = append(ticketIDs, ticketID)
	}
	bufferMutex.Unlock()

	if len(ticketIDs) > 0 {
		log.Printf("Flushing %d buffered tickets on shutdown", len(ticketIDs))
		for _, ticketID := range ticketIDs {
			processBufferedTicket(ticketID)
		}
	}
}

// formatCommitTimestamp formats a timestamp for display in Jira comments
func formatCommitTimestamp(timestamp string) string {
	if timestamp == "" {
		return "Unknown time"
	}

	// Parse the timestamp (Gitea provides ISO 8601 format)
	t, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		// If parsing fails, return the original timestamp
		return timestamp
	}

	// Format as a human-readable date and time
	return t.Format("2006-01-02 15:04:05 MST")
}

// formatAuthorWithLink formats the author name with a profile link if username is valid
func formatAuthorWithLink(authorName, authorUsername, repoURL string) string {
	// Check if username exists and contains no spaces
	if authorUsername != "" && !strings.Contains(authorUsername, " ") {
		// Extract base URL from repository URL (e.g., https://git.ionos.org/repo/name -> https://git.ionos.org)
		if baseURL := extractBaseURL(repoURL); baseURL != "" {
			// Create profile link: [username](https://git.ionos.org/username)
			profileURL := baseURL + "/" + authorUsername
			return fmt.Sprintf("[%s](%s)", authorName, profileURL)
		}
	}
	// Return plain author name if username is invalid or base URL can't be extracted
	return authorName
}

// extractBaseURL extracts the base URL from a repository URL
func extractBaseURL(repoURL string) string {
	if repoURL == "" {
		return ""
	}
	
	// Parse the URL to extract the base (scheme + host)
	if parsedURL, err := url.Parse(repoURL); err == nil {
		return fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
	}
	
	return ""
}

// addCommitLinkToJira adds a comment to the specified Jira ticket with bundled commits
func addCommitLinkToJira(ticketData *TicketCommits) error {
	jiraIssueURL := fmt.Sprintf("%s/rest/api/2/issue/%s/comment", appConfig.Jira.APIURL, ticketData.TicketID)
	log.Printf("Adding comment to Jira issue URL: %s", jiraIssueURL)

	// Sort commits by timestamp (oldest first)
	sort.Slice(ticketData.Commits, func(i, j int) bool {
		// Parse timestamps and compare (Gitea provides ISO 8601 format)
		timeI, errI := time.Parse(time.RFC3339, ticketData.Commits[i].Timestamp)
		timeJ, errJ := time.Parse(time.RFC3339, ticketData.Commits[j].Timestamp)

		// If parsing fails, fall back to string comparison
		if errI != nil || errJ != nil {
			return ticketData.Commits[i].Timestamp < ticketData.Commits[j].Timestamp
		}

		return timeI.Before(timeJ)
	})

	// Build comment text with all commits bundled together
	var commentLines []string

	if len(ticketData.Commits) == 1 {
		// Single commit format (maintain compatibility)
		commit := ticketData.Commits[0]
		displayMessage := strings.SplitN(commit.Message, "\n", 2)[0]
		if len(displayMessage) > 100 {
			displayMessage = displayMessage[:100] + "..."
		}
		formattedTime := formatCommitTimestamp(commit.Timestamp)
		
		// Format author information with profile link
		authorWithLink := formatAuthorWithLink(commit.Author.Name, commit.Author.Username, ticketData.RepoURL)
		authorInfo := authorWithLink
		if commit.Author.Username != "" && commit.Author.Username != commit.Author.Name && !strings.Contains(commit.Author.Username, " ") {
			// If we have a valid username different from name, show both (but the name will already be linked)
			authorInfo = fmt.Sprintf("%s (%s)", authorWithLink, commit.Author.Username)
		}
		
		commentLines = append(commentLines, fmt.Sprintf("Associated Gitea Commit: %s (%s)", displayMessage, commit.ShortID))
		commentLines = append(commentLines, fmt.Sprintf("Commit URL: %s", commit.URL))
		commentLines = append(commentLines, fmt.Sprintf("Commit Date: %s", formattedTime))
		commentLines = append(commentLines, fmt.Sprintf("Author: %s", authorInfo))
		commentLines = append(commentLines, fmt.Sprintf("Repository: %s (%s)", ticketData.RepoName, ticketData.RepoURL))
	} else {
		// Multiple commits format
		commentLines = append(commentLines, fmt.Sprintf("Associated Gitea Commits (%d commits):", len(ticketData.Commits)))
		commentLines = append(commentLines, fmt.Sprintf("Repository: %s (%s)", ticketData.RepoName, ticketData.RepoURL))
		commentLines = append(commentLines, "")

		for i, commit := range ticketData.Commits {
			displayMessage := strings.SplitN(commit.Message, "\n", 2)[0]
			if len(displayMessage) > 80 {
				displayMessage = displayMessage[:80] + "..."
			}
			formattedTime := formatCommitTimestamp(commit.Timestamp)
			
			// Format author information with profile link
			authorWithLink := formatAuthorWithLink(commit.Author.Name, commit.Author.Username, ticketData.RepoURL)
			authorInfo := authorWithLink
			if commit.Author.Username != "" && commit.Author.Username != commit.Author.Name && !strings.Contains(commit.Author.Username, " ") {
				// If we have a valid username different from name, show both (but the name will already be linked)
				authorInfo = fmt.Sprintf("%s (%s)", authorWithLink, commit.Author.Username)
			}
			
			commentLines = append(commentLines, fmt.Sprintf("%d. %s (%s)", i+1, displayMessage, commit.ShortID))
			commentLines = append(commentLines, fmt.Sprintf("   %s", commit.URL))
			commentLines = append(commentLines, fmt.Sprintf("   %s", formattedTime))
			commentLines = append(commentLines, fmt.Sprintf("   Author: %s", authorInfo))
			if i < len(ticketData.Commits)-1 {
				commentLines = append(commentLines, "")
			}
		}
	}

	// Add footer with link to the project
	commentLines = append(commentLines, "")
	commentLines = append(commentLines, "{color:#707070}created via [go-gitea-jira-webhook|https://github.com/xorpaul/go-gitea-jira-webhook]{color}")

	commentText := strings.Join(commentLines, "\n")

	// Create simple API v2 request body
	commentBody := map[string]interface{}{
		"body": commentText,
	}
	// Add visibility if configured and not forced to be public
	if appConfig.Jira.CommentVisibility != "" && !ticketData.ForcePublic {
		// Format: "role:Members" or "group:SomeGroup"
		parts := strings.SplitN(appConfig.Jira.CommentVisibility, ":", 2)
		if len(parts) == 2 {
			commentBody["visibility"] = map[string]interface{}{
				"type":  parts[0],
				"value": parts[1],
			}
		}
	}

	if ticketData.ForcePublic {
		log.Printf("Comment for ticket %s will be public ($ prefix used)", ticketData.TicketID)
	}

	jsonBody, err := json.Marshal(commentBody)
	if err != nil {
		return fmt.Errorf("error marshaling Jira comment body: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, jiraIssueURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("error creating Jira API request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", jiraAPIToken))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request to Jira API: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	// Check for authorization failure and attempt token renewal
	if resp.StatusCode == http.StatusUnauthorized {
		log.Printf("Jira API returned 401 Unauthorized. Attempting to refresh token and retry...")

		// Refresh the token
		if err := refreshJiraToken(); err != nil {
			return fmt.Errorf("token refresh failed after 401 error: %w", err)
		}

		// Retry the request with the new token
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", jiraAPIToken))
		resp2, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("error sending retry request to Jira API: %w", err)
		}
		defer resp2.Body.Close()

		respBody2, _ := io.ReadAll(resp2.Body)
		if resp2.StatusCode != http.StatusCreated && resp2.StatusCode != http.StatusOK {
			return fmt.Errorf("Jira API retry returned non-success status: %d - %s", resp2.StatusCode, string(respBody2))
		}

		log.Printf("Received successfully response from Jira API for ticket %s after token refresh - %s", ticketData.TicketID, string(respBody2))
		return nil
	}

	// Handle other non-success status codes
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Jira API returned non-success status: %d - %s", resp.StatusCode, string(respBody))
	}

	log.Printf("Received successfully response from Jira API for ticket %s - %s", ticketData.TicketID, string(respBody))

	return nil
}

func main() {
	// Define command line flags
	var (
		versionFlag = flag.Bool("version", false, "Show version information")
		helpFlag    = flag.Bool("help", false, "Show help information")
		configFlag  = flag.String("config", defaultConfigPath, "Path to configuration file")
	)

	flag.Parse()

	if *helpFlag {
		fmt.Printf("Go Gitea Jira Webhook - Receives Gitea webhooks and adds comments to Jira tickets\n\n")
		fmt.Printf("Usage: %s [options]\n\n", os.Args[0])
		fmt.Printf("Options:\n")
		fmt.Printf("  -version          Show version information (default: false)\n")
		fmt.Printf("  -help             Show this help message (default: false)\n")
		fmt.Printf("  -config string    Path to configuration file (default: \"%s\")\n", defaultConfigPath)
		fmt.Printf("\nExample:\n")
		fmt.Printf("  %s -config /path/to/config.toml\n", os.Args[0])
		fmt.Printf("  %s -version\n", os.Args[0])
		return
	}

	if *versionFlag {
		fmt.Printf("Build version: %s\n", buildversion)
		fmt.Printf("Build time: %s\n", buildtime)
		return
	}

	// Determine config path from command line or environment variable
	configPath := *configFlag
	if envConfigPath := os.Getenv("CONFIG_FILE_PATH"); envConfigPath != "" {
		configPath = envConfigPath
		log.Printf("Using configuration file from CONFIG_FILE_PATH environment variable: %s", configPath)
	} else {
		log.Printf("Using configuration file: %s", configPath)
	}

	// Load and validate configuration
	if err := loadConfiguration(configPath); err != nil {
		log.Fatalf("Configuration error: %v", err)
	}

	// Start periodic token renewal checker
	startPeriodicTokenRenewal()

	// Combined handler for root path - GET for overview, POST for webhooks
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			serviceOverviewHandler(w, r)
		} else if r.Method == http.MethodPost {
			giteaWebhookHandler(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// Dedicated webhook handler
	http.HandleFunc("/gitea-webhook", giteaWebhookHandler)

	// Image handler for service overview page
	http.HandleFunc("/go-gitea-jira-webhook.jpg", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Only GET requests are accepted for images", http.StatusMethodNotAllowed)
			return
		}

		// Read the embedded image file
		imageData, err := embeddedImage.ReadFile("go-gitea-jira-webhook.jpg")
		if err != nil {
			log.Printf("Error reading embedded image: %v", err)
			http.Error(w, "Image not found", http.StatusNotFound)
			return
		}

		// Set the appropriate content type and serve the image
		w.Header().Set("Content-Type", "image/jpeg")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(imageData)))
		w.Write(imageData)
	})

	// Use port from config, or default to 8443 if not set
	port := appConfig.Server.Port
	if port == "" {
		port = "8443"
	}
	addr := ":" + port

	log.Printf("Starting HTTPS server on %s", addr)
	log.Printf("Using certificate file: %s", appConfig.SSL.CertFile)
	log.Printf("Using key file: %s", appConfig.SSL.KeyFile)

	// Create server for graceful shutdown
	server := &http.Server{
		Addr: addr,
	}

	// Handle graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		log.Println("Received shutdown signal, flushing buffered tickets...")
		flushAllBufferedTickets()

		log.Println("Shutting down server...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	}()

	log.Fatal(server.ListenAndServeTLS(appConfig.SSL.CertFile, appConfig.SSL.KeyFile))
}
