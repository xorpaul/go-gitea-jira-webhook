package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/BurntSushi/toml" // Import the TOML library
)

// Build version variables - set via ldflags during build
var (
	buildtime    = "unknown"
	buildversion = "unknown"
)

// Config represents the structure of our TOML configuration file
type Config struct {
	Jira struct {
		APIURL   string `toml:"api_url"`
		Username string `toml:"username"`
		APIToken string `toml:"api_token"`
	} `toml:"jira"`
	Gitea struct {
		WebhookSecret string `toml:"webhook_secret"` // Optional
	} `toml:"gitea"`
	SSL struct {
		CertFile string `toml:"cert_file"`
		KeyFile  string `toml:"key_file"`
	} `toml:"ssl"`
	Server struct {
		Port string `toml:"port"` // Can also be hardcoded to 8443
	} `toml:"server"`
}

// Global variables to hold configuration and compiled regex
var (
	appConfig       Config
	jiraTicketRegex *regexp.Regexp
)

func init() {
	// 1. Determine config file path from environment variable or default
	configPath := os.Getenv("CONFIG_FILE_PATH")
	if configPath == "" {
		// As per requirement, expect it under /etc/gitea-jira-webhook/config.toml
		configPath = "/etc/gitea-jira-webhook/config.toml"
		log.Printf("CONFIG_FILE_PATH environment variable not set, defaulting to %s", configPath)
	}

	// 2. Load configuration from TOML file
	if _, err := toml.DecodeFile(configPath, &appConfig); err != nil {
		log.Fatalf("Error loading configuration from %s: %v", configPath, err)
	}

	// 3. Validate essential config fields
	if appConfig.Jira.APIURL == "" {
		log.Fatal("Jira.APIURL is not set in the configuration file.")
	}
	if appConfig.Jira.Username == "" {
		log.Fatal("Jira.Username is not set in the configuration file.")
	}
	if appConfig.Jira.APIToken == "" {
		log.Fatal("Jira.APIToken is not set in the configuration file.")
	}
	if appConfig.SSL.CertFile == "" {
		log.Fatal("SSL.CertFile is not set in the configuration file.")
	}
	if appConfig.SSL.KeyFile == "" {
		log.Fatal("SSL.KeyFile is not set in the configuration file.")
	}

	// 4. Compile the regex once at startup
	jiraTicketRegex = regexp.MustCompile(`\b([A-Z]+-[0-9]+)\b`)

	log.Println("Service initialized and configuration loaded.")
	log.Printf("JIRA API URL: %s", appConfig.Jira.APIURL)
	if appConfig.Gitea.WebhookSecret != "" {
		log.Println("Gitea webhook secret is configured.")
	} else {
		log.Println("WARNING: Gitea webhook secret is NOT configured. Webhook requests will not be verified.")
	}
	log.Printf("Listening with TLS. Cert File: %s, Key File: %s", appConfig.SSL.CertFile, appConfig.SSL.KeyFile)
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
			Name  string `json:"name"`
			Email string `json:"email"`
		} `json:"author"`
	} `json:"commits"`
	Repository struct {
		Name        string `json:"name"`
		FullName    string `json:"full_name"`
		HTMLURL     string `json:"html_url"`
		Description string `json:"description"`
	} `json:"repository"`
	Pusher struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	} `json:"pusher"`
	Sender struct {
		ID        int    `json:"id"`
		Login     string `json:"login"`
		HTMLURL   string `json:"html_url"`
		AvatarURL string `json:"avatar_url"`
	} `json:"sender"`
}

// JiraCommentBody represents the structure for adding a comment to Jira
type JiraCommentBody struct {
	Body struct {
		Type    string `json:"type"`
		Version int    `json:"version"`
		Content []struct {
			Type    string `json:"type"`
			Content []struct {
				Type  string `json:"type"`
				Text  string `json:"text"`
				Marks []struct {
					Type  string `json:"type"`
					Attrs struct {
						Href string `json:"href"`
					} `json:"attrs,omitempty"`
				} `json:"marks,omitempty"`
			} `json:"content"`
		} `json:"content"`
	} `json:"body"`
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

// giteaWebhookHandler handles incoming Gitea webhook POST requests
func giteaWebhookHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST requests are accepted", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading request body: %v", err)
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

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

	for _, commit := range payload.Commits {
		commitID := commit.ID
		commitMessage := commit.Message
		commitURL := commit.URL
		repoURL := payload.Repository.HTMLURL
		repoName := payload.Repository.Name

		log.Printf("Processing commit %s: '%s'", commitID[:7], commitMessage)

		foundJiraTickets := jiraTicketRegex.FindAllStringSubmatch(commitMessage, -1)
		if len(foundJiraTickets) > 0 {
			uniqueTickets := make(map[string]struct{})
			for _, match := range foundJiraTickets {
				if len(match) > 1 {
					uniqueTickets[match[1]] = struct{}{}
				}
			}

			for ticketID := range uniqueTickets {
				log.Printf("Found Jira ticket '%s' in commit %s. Attempting to update Jira.", ticketID, commitID[:7])
				if err := addCommitLinkToJira(ticketID, commitURL, commitMessage, commitID, repoURL, repoName); err != nil {
					log.Printf("Failed to update Jira ticket %s: %v", ticketID, err)
				} else {
					log.Printf("Successfully updated Jira ticket %s with commit %s.", ticketID, commitID[:7])
				}
			}
		} else {
			log.Printf("No Jira tickets found in commit %s.", commitID[:7])
		}
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "Webhook processed successfully")
}

// addCommitLinkToJira adds a comment to the specified Jira ticket with a link to the Gitea commit
func addCommitLinkToJira(jiraTicketID, commitURL, commitMessage, commitID, repoURL, repoName string) error {
	jiraIssueURL := fmt.Sprintf("%s/issue/%s/comment", appConfig.Jira.APIURL, jiraTicketID) // Use appConfig.Jira.APIURL

	displayMessage := strings.SplitN(commitMessage, "\n", 2)[0]
	if len(displayMessage) > 100 {
		displayMessage = displayMessage[:100] + "..."
	}

	commentBody := JiraCommentBody{
		Body: struct {
			Type    string `json:"type"`
			Version int    `json:"version"`
			Content []struct {
				Type    string `json:"type"`
				Content []struct {
					Type  string `json:"type"`
					Text  string `json:"text"`
					Marks []struct {
						Type  string `json:"type"`
						Attrs struct {
							Href string `json:"href"`
						} `json:"attrs,omitempty"`
					} `json:"marks,omitempty"`
				} `json:"content"`
			} `json:"content"`
		}{
			Type:    "doc",
			Version: 1,
			Content: []struct {
				Type    string `json:"type"`
				Content []struct {
					Type  string `json:"type"`
					Text  string `json:"text"`
					Marks []struct {
						Type  string `json:"type"`
						Attrs struct {
							Href string `json:"href"`
						} `json:"attrs,omitempty"`
					} `json:"marks,omitempty"`
				} `json:"content"`
			}{
				{
					Type: "paragraph",
					Content: []struct {
						Type  string `json:"type"`
						Text  string `json:"text"`
						Marks []struct {
							Type  string `json:"type"`
							Attrs struct {
								Href string `json:"href"`
							} `json:"attrs,omitempty"`
						} `json:"marks,omitempty"`
					}{
						{
							Type: "text",
							Text: "Associated Gitea Commit: ",
						},
						{
							Type: "text",
							Text: fmt.Sprintf("%s (%s)", displayMessage, commitID[:7]),
							Marks: []struct {
								Type  string `json:"type"`
								Attrs struct {
									Href string `json:"href"`
								} `json:"attrs,omitempty"`
							}{
								{
									Type: "link",
									Attrs: struct {
										Href string `json:"href"`
									}{Href: commitURL},
								},
							},
						},
						{
							Type: "text",
							Text: " in repository ",
						},
						{
							Type: "text",
							Text: repoName,
							Marks: []struct {
								Type  string `json:"type"`
								Attrs struct {
									Href string `json:"href"`
								} `json:"attrs,omitempty"`
							}{
								{
									Type: "link",
									Attrs: struct {
										Href string `json:"href"`
									}{Href: repoURL},
								},
							},
						},
					},
				},
			},
		},
	}

	jsonBody, err := json.Marshal(commentBody)
	if err != nil {
		return fmt.Errorf("error marshaling Jira comment body: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, jiraIssueURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("error creating Jira API request: %w", err)
	}

	req.SetBasicAuth(appConfig.Jira.Username, appConfig.Jira.APIToken) // Use appConfig.Jira.Username, appConfig.Jira.APIToken
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request to Jira API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Jira API returned non-success status: %d - %s", resp.StatusCode, string(respBody))
	}

	return nil
}

func main() {
	// Parse version flag
	versionFlag := flag.Bool("version", false, "Show version information")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("Build version: %s\n", buildversion)
		fmt.Printf("Build time: %s\n", buildtime)
		return
	}

	http.HandleFunc("/gitea-webhook", giteaWebhookHandler)

	// Use port from config, or default to 8443 if not set
	port := appConfig.Server.Port
	if port == "" {
		port = "8443"
	}
	addr := ":" + port

	log.Printf("Starting HTTPS server on %s", addr)
	log.Printf("Using certificate file: %s", appConfig.SSL.CertFile)
	log.Printf("Using key file: %s", appConfig.SSL.KeyFile)

	log.Fatal(http.ListenAndServeTLS(addr, appConfig.SSL.CertFile, appConfig.SSL.KeyFile, nil))
}
