#!/usr/bin/env bash
# Builds the golangci-lint pinned in .pre-commit-config.yaml into .cache/bin.
set -euo pipefail

cd "$(dirname "$0")/.."

version="$(awk '/repo: https:\/\/github.com\/golangci\/golangci-lint$/ {found = 1} found && $1 == "rev:" {print $2; exit}' .pre-commit-config.yaml)"
if [[ -z "${version}" ]]; then
  echo "tools: .pre-commit-config.yaml names no golangci-lint rev" >&2
  exit 1
fi

go_version="$(go env GOVERSION)"
bin="${PWD}/.cache/bin"

# The linter refuses a module newer than the Go that built it, so a cached
# binary is kept only when both its version and its Go match.
if [[ -x "${bin}/golangci-lint" ]]; then
  built="$(go version -m "${bin}/golangci-lint")"
  if grep -q ": ${go_version}\$" <<<"${built}" &&
    grep -qE "^[[:space:]]+mod[[:space:]]+github.com/golangci/golangci-lint/v2[[:space:]]+${version}[[:space:]]" <<<"${built}"; then
    exit 0
  fi
fi

echo "tools: building golangci-lint ${version} with ${go_version}" >&2
GOTOOLCHAIN="${go_version}" GOBIN="${bin}" go install "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@${version}"
