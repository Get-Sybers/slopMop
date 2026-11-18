#!/usr/bin/env bash
# Sets the `release` environment of the repository up, once: a reviewer, the
# key that signs and the token of the registry. Needs gh, signed in as an
# owner of the repository, and gpg. Usage: release-setup.sh [owner/repo]
set -euo pipefail

cd "$(dirname "$0")/.."
repo="${1:-$(gh repo view --json nameWithOwner --jq .nameWithOwner)}"

# Whoever runs this approves a publish before it runs.
gh api --method PUT "repos/${repo}/environments/release" --input - >/dev/null <<EOF
{"reviewers": [{"type": "User", "id": $(gh api user --jq .id)}]}
EOF

# The key is made in a keyring of its own, and the one copy of its secret half
# goes to the environment: the keyring is removed when this ends.
GNUPGHOME="$(mktemp -d)"
export GNUPGHOME
trap 'gpgconf --kill gpg-agent; rm -rf "${GNUPGHOME}"' EXIT
gpg --batch --quiet --pinentry-mode loopback --passphrase '' --quick-generate-key "slopMop release signing" ed25519 sign 2y
gpg --batch --pinentry-mode loopback --passphrase '' --armor --export-secret-keys |
  gh secret set GPG_PRIVATE_KEY --env release --repo "${repo}"
gpg --armor --export >release-key.asc

echo "The token that pushes to ghcr.io, a classic personal access token with write:packages:"
gh secret set GHCR_TOKEN --env release --repo "${repo}"

echo "release-key.asc holds the public key: commit it. Its fingerprint:"
gpg --show-keys --with-colons release-key.asc 2>/dev/null | awk -F: '$1 == "fpr" { print $10; exit }'
