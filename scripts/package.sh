#!/usr/bin/env bash
# Packs the built binary and its checksum as an OCI artifact in a layout on
# disk, then pulls the artifact back and checks what comes out.
# Usage: package.sh <dist> <version> <layout>
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
dist="$(realpath "$1")"
version="$2"
layout="$(realpath -m "$3")"
exe="slopmop-${version}-windows-amd64.exe"

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

# A file is a layer under its own name, so a pull writes the two files. The
# time is that of the commit: the same build packs to the same digest.
cd "${dist}"
oras push --oci-layout "${layout}:${version}" \
  --artifact-type application/vnd.get-sybers.slopmop \
  --annotation "org.opencontainers.image.title=slopmop" \
  --annotation "org.opencontainers.image.description=A static-analysis tool for a folder of scripts an AI agent wrote and the outputs those scripts produced." \
  --annotation "org.opencontainers.image.licenses=MIT" \
  --annotation "org.opencontainers.image.source=${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-Get-Sybers/slopMop}" \
  --annotation "org.opencontainers.image.version=${version}" \
  --annotation "org.opencontainers.image.revision=$(git -C "${root}" rev-parse HEAD)" \
  --annotation "org.opencontainers.image.created=$(TZ=UTC0 git -C "${root}" log -1 --date=format-local:%Y-%m-%dT%H:%M:%SZ --format=%cd)" \
  "${exe}:application/vnd.microsoft.portable-executable" \
  "${exe}.sha256:text/plain"

oras pull --oci-layout "${layout}:${version}" --output "${work}/pulled"
cd "${work}/pulled"
sha256sum --check "${exe}.sha256"
