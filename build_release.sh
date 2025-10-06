#!/usr/bin/env bash
set -euo pipefail
rm build/* || true

echo "Starting tests..."
go test -v ./...

export CGO_ENABLED=0
if [ $# -eq 0 ]; then
	echo "Error: version parameter is required (e.g., 1.0.0)" >&2
	exit 1
fi

if [[ "$1" == v* ]]; then
	V="$1"
else
	V="v$1"
fi

# use current directory name as project name
PROJECTNAME=$(basename "$(pwd)")
UPX=$(which upx)
UPX_COMPRESSION_LEVEL=5
BUILDTIME=$(date -u '+%Y-%m-%d_%H:%M:%S')
GOPARAMS="-s -w -X main.buildtime=$BUILDTIME -X main.buildversion=${V}"

# Read build configuration from .build.cfg if it exists
# Default to all platforms if no config file exists
BUILD_LINUX=true
BUILD_MACOS_AMD64=true
BUILD_MACOS_ARM64=true
BUILD_WINDOWS=true

if [ -f ".build.cfg" ]; then
	echo "Found .build.cfg, reading build configuration..."
	# Reset defaults to false when config file exists
	BUILD_LINUX=false
	BUILD_MACOS_AMD64=false
	BUILD_MACOS_ARM64=false
	BUILD_WINDOWS=false

	# Source the config file
	source .build.cfg

	echo "Build configuration:"
	echo "  Linux AMD64: $BUILD_LINUX"
	echo "  macOS AMD64: $BUILD_MACOS_AMD64"
	echo "  macOS ARM64: $BUILD_MACOS_ARM64"
	echo "  Windows AMD64: $BUILD_WINDOWS"
else
	echo "No .build.cfg found, building for all platforms"
fi

# Build for Linux AMD64
if [ "$BUILD_LINUX" = true ]; then
	echo "Building for Linux AMD64..."
	env GOOS=linux GOARCH=amd64 go build -ldflags "${GOPARAMS}" -o build/${PROJECTNAME}_${V}_linux-amd64
	if [ ${#UPX} -gt 0 ]; then
		${UPX} -${UPX_COMPRESSION_LEVEL} build/${PROJECTNAME}_${V}_linux-amd64
	fi
fi

# Build for macOS AMD64
if [ "$BUILD_MACOS_AMD64" = true ]; then
	echo "Building for macOS AMD64..."
	env GOOS=darwin GOARCH=amd64 go build -ldflags "${GOPARAMS}" -o build/${PROJECTNAME}_${V}_macos-amd64
fi

# Build for macOS ARM64
if [ "$BUILD_MACOS_ARM64" = true ]; then
	echo "Building for macOS ARM64..."
	env GOOS=darwin GOARCH=arm64 go build -ldflags "${GOPARAMS}" -o build/${PROJECTNAME}_${V}_macos-arm64
fi

# Build for Windows AMD64
if [ "$BUILD_WINDOWS" = true ]; then
	echo "Building for Windows AMD64..."
	env GOOS=windows GOARCH=amd64 go build -ldflags "${GOPARAMS}" -o build/${PROJECTNAME}_${V}_windows-amd64.exe
	if [ ${#UPX} -gt 0 ]; then
		${UPX} -${UPX_COMPRESSION_LEVEL} build/${PROJECTNAME}_${V}_windows-amd64.exe
	fi
fi

# create and upload to gitea
if [ -f ~/.gitea_env ]; then
	echo "Creating release on Gitea..."
	source ~/.gitea_env

	# Auto-detect repo owner, name, and URL from git remote
	# Extract from remote URL like: https://git.ionos.org/PUKI/go-vpn-selfservice.git
	# or SSH: gitea@git.ionos.org:PUKI/go-vpn-selfservice.git
	REMOTE_URL=$(git remote get-url origin)
	echo "Git remote URL: ${REMOTE_URL}"

	# Extract repo path and base URL from remote (handles both HTTPS and SSH formats)
	if [[ "$REMOTE_URL" =~ (.*)@([^:]+):(.+)\.git$ ]]; then
		# SSH format: gitea@git.ionos.org:PUKI/go-vpn-selfservice.git
		GITEA_HOST="${BASH_REMATCH[2]}"
		REPO_PATH="${BASH_REMATCH[3]}"
		GITEA_URL="https://${GITEA_HOST}"
	elif [[ "$REMOTE_URL" =~ (https?://[^/]+)/(.+)\.git$ ]]; then
		# HTTPS format: https://git.ionos.org/PUKI/go-vpn-selfservice.git
		GITEA_URL="${BASH_REMATCH[1]}"
		REPO_PATH="${BASH_REMATCH[2]}"
	else
		echo "Error: Could not parse git remote URL: ${REMOTE_URL}"
		exit 1
	fi

	GITEA_REPO_OWNER=$(dirname "$REPO_PATH")
	GITEA_REPO_NAME=$(basename "$REPO_PATH")

	# Auto-detect current branch
	CURRENT_BRANCH=$(git branch --show-current)

	echo "Detected Gitea URL: ${GITEA_URL}"
	echo "Detected repo: ${GITEA_REPO_OWNER}/${GITEA_REPO_NAME}"
	echo "Current branch: ${CURRENT_BRANCH}"

	# Create git tag if it doesn't exist
	if ! git rev-parse "${V}" >/dev/null 2>&1; then
		echo "Creating git tag: ${V}"
		git tag -a "${V}" -m "Release ${V}"
		git push origin "${V}"
	else
		echo "Git tag ${V} already exists"
	fi

	# Get the commit SHA for the tag
	TAG_COMMIT=$(git rev-parse "${V}")
	echo "Tag ${V} points to commit: ${TAG_COMMIT}"

	# Check if release already exists
	EXISTING_RELEASE=$(curl -s -H "Authorization: token ${GITEA_TOKEN}" \
		"${GITEA_URL}/api/v1/repos/${GITEA_REPO_OWNER}/${GITEA_REPO_NAME}/releases/tags/${V}")

	if echo "$EXISTING_RELEASE" | jq -e '.id' >/dev/null 2>&1; then
		echo "Release for tag ${V} already exists, getting existing release ID..."
		RELEASE_ID=$(echo "$EXISTING_RELEASE" | jq -r '.id')
		echo "Using existing release ID: $RELEASE_ID"
	else
		echo "Creating new release for tag ${V}..."
		# create a new release
		RELEASE_RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" -H "Authorization: token ${GITEA_TOKEN}" \
			-d "{\"tag_name\":\"${V}\",\"target_commitish\":\"${TAG_COMMIT}\",\"name\":\"${V}\",\"body\":\"Release ${V} ${2}\",\"draft\":false,\"prerelease\":false}" \
			"${GITEA_URL}/api/v1/repos/${GITEA_REPO_OWNER}/${GITEA_REPO_NAME}/releases")

		echo "$RELEASE_RESPONSE" | jq .

		# Extract release ID from response
		RELEASE_ID=$(echo "$RELEASE_RESPONSE" | jq -r '.id')

		if [ "$RELEASE_ID" = "null" ] || [ -z "$RELEASE_ID" ]; then
			echo "Error: Failed to create release or extract release ID"
			exit 1
		fi

		echo "Release created with ID: $RELEASE_ID"
	fi

	# upload the binaries
	for FILE in build/*; do
		echo "Uploading ${FILE} to Gitea..."
		FILENAME=$(basename "${FILE}")
		curl -s -X POST -H "Authorization: token ${GITEA_TOKEN}" \
			-F "attachment=@${FILE}" \
			"${GITEA_URL}/api/v1/repos/${GITEA_REPO_OWNER}/${GITEA_REPO_NAME}/releases/${RELEASE_ID}/assets?name=${FILENAME}" | jq .
	done
else
	echo "Skipping Gitea release creation, .gitea_env file not found."
fi
