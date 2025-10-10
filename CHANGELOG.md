# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v0.0.2.html).

## [Unreleased]

### Added

- **Immediate Posting with `%` Prefix**: Added support for `%TICKETID` format to skip buffering and post comments immediately
- **Immediate Posting with `!` Suffix**: Added support for `TICKETID!` format as alternative to `%` prefix for immediate posting
- **Combined Prefix Support**: Support for combinations like `#%TICKETID`, `$%TICKETID`, `#TICKETID!`, `$TICKETID!` to combine public visibility with immediate posting
- **Enhanced Regex Pattern**: Updated pattern to `(^|[^A-Za-z0-9-!])([\$#%]*[A-Z]+-[0-9]+!?)(?:[^A-Za-z0-9-!]|$)` to support multiple prefixes and suffix
- **Comprehensive Testing**: Added 23 test cases covering all prefix and suffix combinations
- **Enhanced Logging**: Added detailed logging showing which prefixes/suffixes triggered specific behaviors

### Enhanced

- **Ticket Processing**: Modified buffering logic to bypass when `ForceImmediate` flag is set
- **Data Structures**: Added `ForceImmediate` field to `TicketCommits` struct
- **Documentation**: Updated README.md, example.toml, and web interface with new syntax options

### Technical Implementation

- **Prefix Processing**: Enhanced parsing logic to handle multiple prefix characters (`$`, `#`, `%`) in any combination
- **Suffix Processing**: Added detection and processing of `!` suffix at end of ticket IDs
- **Immediate Posting**: Tickets with `%` prefix or `!` suffix bypass buffering and post immediately
- **Public Visibility**: Tickets with `#` or `$` prefix force public visibility regardless of `comment_visibility` setting

## [v0.0.5] - 2025-10-08

### Added

- **Commit Author Information**: Added commit author name and email to Jira comments
- **Profile Links**: Added automatic links to Gitea user profiles when username is available and contains no spaces
- **Author Display**: Enhanced comment format to include "by @username" or "by Name (email)" depending on available information

### Technical Implementation

- Enhanced `CommitInfo` struct with author fields (Name, Email, Username)
- Added `formatAuthorWithLink()` function to generate profile links
- Added `extractBaseURL()` function to derive Gitea base URL from repository URL
- Profile links use format: `{giteaBaseURL}/{username}` when username is valid

## [v0.0.4] - 2025-10-06

### Added

- **Bash-Safe Public Comments**: Added support for `#TICKETID` format as alternative to `$TICKETID` for public visibility
- **Enhanced Regex Pattern**: Updated to support both `$` and `#` prefixes for public comment override

### Fixed

- **Critical Regex Bug**: Fixed regex pattern that was not properly capturing `#` and `$` prefixes
  - **Old pattern**: `\b([\$#]?[A-Z]+-[0-9]+)\b` (broken - prefixes not captured)
  - **New pattern**: `(^|[^A-Za-z0-9-])([\$#]?[A-Z]+-[0-9]+)(?:[^A-Za-z0-9-]|$)` (working)
- **Parsing Logic**: Updated to use correct capture group (`match[2]` instead of `match[1]`)

### Technical Implementation

- Fixed word boundary issues with special characters in regex patterns
- Added comprehensive debugging and logging for ticket parsing
- Created test suite with 15 test cases to verify regex behavior
- `#TICKETID` format prevents bash variable expansion issues while maintaining public visibility

## [v0.0.3] - 2025-09-25

### New Features

- **IP Restrictions**: Optional CIDR-based IP filtering for webhook POST requests
- **Service Overview Web Page**: HTTP GET endpoint at root path showing service configuration and status
- **Embedded Image Serving**: Serves `go-gitea-jira-webhook.jpg` directly from embedded filesystem
- **Enhanced Security**: Support for proxy headers (X-Forwarded-For, X-Real-IP) in IP validation

### Improvements

- **Web Interface**: Clean HTML interface showing service configuration, API endpoints, and usage instructions
- **Configuration Display**: Shows current settings for Jira, buffering, IP restrictions, and webhook security
- **Usage Instructions**: In-app documentation with examples and configuration guidance

### Implementation Details

- Added `allowed_cidrs` configuration option in TOML
- Implemented `isIPAllowed()` and `getClientIP()` functions for IP validation
- Used `embed.FS` to serve static assets without external file dependencies
- Enhanced service overview with embedded image and comprehensive status information

### Configuration Example

```toml
[server]
allowed_cidrs = ["192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/12"]
```

## [v0.0.2] - 2025-09-12

### New Features

- **Project Image**: Added `go-gitea-jira-webhook.jpg` logo/image file
- **Build Script**: Added `build_release.sh` for automated building and releases
- **Enhanced Documentation**: Updated README with project image and build instructions

### Implementation Details

- Added visual branding for the project
- Established build and release workflow
- Improved project documentation and presentation

## [v0.0.1] - 2024-XX-XX (Initial Release)

### Foundation Features

- **Core Webhook Functionality**: Gitea webhook receiver that processes push events and creates Jira comments
- **Jira Integration**: Automatic API token creation, caching, and renewal with 90-day expiry
- **Commit Buffering**: Optional buffering system to batch multiple commits into single comments
- **Public Visibility Override**: `$TICKETID` format to force public Jira comments bypassing `comment_visibility` settings
- **HMAC Security**: Webhook signature verification using configured secret
- **HTTPS/TLS Support**: SSL certificate configuration for secure communication
- **Project Filtering**: Optional filtering to process only specific Jira projects

### Core Capabilities

- **Regex Pattern Matching**: Extracts Jira ticket IDs from commit messages using `\b(\$?[A-Z]+-[0-9]+)\b`
- **Comment Visibility Control**: Configurable comment visibility (role, group) with public override capability
- **Commit Bundling**: Multiple commits referencing same ticket are bundled into single comment
- **Token Management**: Automatic Jira API token lifecycle management
- **Configuration**: TOML-based configuration with comprehensive options

### Configuration Structure

```toml
[jira]
api_url = "https://your-jira-instance.atlassian.net/rest/api/3"
username = "your-jira-username"
password = "your-jira-password"
projects_filter = ["PROJECT1", "PROJECT2"]
comment_visibility = "role:Members"

[gitea]
webhook_secret = "your-webhook-secret"

[ssl]
cert_file = "/path/to/cert.pem"
key_file = "/path/to/key.pem"

[server]
port = "8443"

[buffering]
duration = "10m"
```

### Architecture Overview

- **Language**: Go with standard library + TOML parsing
- **Security**: HMAC-SHA256 webhook verification, TLS/SSL support
- **Reliability**: Automatic token renewal, graceful error handling
- **Performance**: Configurable buffering to reduce API calls and comment spam

---

## Feature Matrix

| Format       | Public Visibility | Processing    | Use Case                             |
| ------------ | ----------------- | ------------- | ------------------------------------ |
| `PROJ-123`   | Configured        | Buffered      | Normal development                   |
| `#PROJ-123`  | **Public**        | Buffered      | Public fixes (bash-safe)             |
| `$PROJ-123`  | **Public**        | Buffered      | Public fixes                         |
| `%PROJ-123`  | Configured        | **Immediate** | Urgent private fixes                 |
| `PROJ-123!`  | Configured        | **Immediate** | Urgent private fixes (alternative)   |
| `#%PROJ-123` | **Public**        | **Immediate** | Critical public fixes                |
| `#PROJ-123!` | **Public**        | **Immediate** | Critical public fixes (alternative)  |
| `$%PROJ-123` | **Public**        | **Immediate** | Emergency public fixes               |
| `$PROJ-123!` | **Public**        | **Immediate** | Emergency public fixes (alternative) |

## Links

- [Repository](https://github.com/xorpaul/go-gitea-jira-webhook)
- [Releases](https://github.com/xorpaul/go-gitea-jira-webhook/releases)
- [Issues](https://github.com/xorpaul/go-gitea-jira-webhook/issues)
