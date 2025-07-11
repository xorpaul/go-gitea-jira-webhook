# Go Gitea Jira Webhook

A Go application that receives webhooks from Gitea and automatically adds comments to Jira tickets when commits reference ticket IDs.

## Features

- Receives Gitea push webhooks
- Extracts Jira ticket IDs from commit messages using regex pattern `\b([A-Z]+-[0-9]+)\b`
- Automatically adds comments to Jira tickets with commit links
- Supports HMAC signature verification for webhook security
- Configurable via TOML configuration file
- HTTPS/TLS support

## Configuration

The application expects a TOML configuration file. The configuration file path is determined in the following order of precedence:

1. Command line flag: `-config /path/to/config.toml`
2. Default location: `/etc/gitea-jira-webhook/config.toml`

Example configuration:

```toml
[jira]
api_url = "https://your-jira-instance.atlassian.net/rest/api/3"
username = "your-jira-username"
api_token = "your-jira-api-token"

[gitea]
webhook_secret = "your-webhook-secret"  # Optional

[ssl]
cert_file = "/path/to/cert.pem"
key_file = "/path/to/key.pem"

[server]
port = "8443"
```

## Building

### Build with Version Information

To build the binary with build time and version information:

```bash
BUILDTIME=$(date -u '+%Y-%m-%d_%H:%M:%S') BUILDVERSION="$(git describe --tags)" && go build -race -ldflags "-X main.buildtime=$BUILDTIME -X main.buildversion=${BUILDVERSION}" && ./go-gitea-jira-webhook -version
```

### Standard Build

```bash
go build
```

## Version Information

To check the version of the built binary:

```bash
./go-gitea-jira-webhook -version
```

## Refreshing Go Modules

To refresh and update all Go modules:

```bash
rm go.??? ; rm -rf vendor ; go mod init ; go get -u && go mod tidy && go mod vendor ; echo GOREFRESH
```

## Usage

### Command Line Options

```bash
./go-gitea-jira-webhook [options]
```

Available options:

- `-version` - Show version information
- `-help` - Show help information with all available options and their defaults
- `-config string` - Path to configuration file (default: "/etc/gitea-jira-webhook/config.toml")

Examples:

```bash
# Show help
./go-gitea-jira-webhook -help

# Show version
./go-gitea-jira-webhook -version

# Use custom config file
./go-gitea-jira-webhook -config /path/to/my-config.toml

# Run with default settings
./go-gitea-jira-webhook
```

### Setup Steps

1. Configure your TOML configuration file
2. Build the binary using the build command above
3. Run the application:
   ```bash
   ./go-gitea-jira-webhook
   ```
4. Configure your Gitea repository webhook to point to: `https://your-server:8443/gitea-webhook`

## How It Works

1. Gitea sends a webhook POST request to `/gitea-webhook` endpoint
2. The application verifies the webhook signature (if configured)
3. Extracts commit messages from the push event
4. Searches for Jira ticket IDs in commit messages using regex
5. For each found ticket ID, adds a comment to the Jira ticket with:
   - Link to the commit
   - Commit message (truncated if too long)
   - Repository information

## Security

- Webhook signature verification using HMAC-SHA256
- HTTPS/TLS required for all communications
- Basic authentication for Jira API calls

## License

[Add your license information here]
