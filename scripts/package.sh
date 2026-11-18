#!/usr/bin/env bash
# Signs the built binary and packs it, with its checksum and its signature, as
# an OCI artifact in a layout on disk, then pulls the artifact back and checks
# what comes out. Usage: package.sh <dist> <version> <public key> <layout>
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
dist="$(realpath "$1")"
version="$2"
key="$(realpath "$3")"
layout="$(realpath -m "$4")"
exe="slopmop-${version}-windows-amd64.exe"

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

# The one secret key of the keyring signs. The signature holds when the public
# key given verifies it with no other key at hand.
gpg --batch --yes --pinentry-mode loopback --passphrase-fd 3 --armor --detach-sign \
  --output "${dist}/${exe}.asc" "${dist}/${exe}" 3<<<"${GPG_PASSPHRASE:-}"
gpg --dearmor <"${key}" >"${work}/key.gpg"
gpgv --keyring "${work}/key.gpg" "${dist}/${exe}.asc" "${dist}/${exe}"

# A file is a layer under its own name, so a pull writes the three files.
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
  "${exe}.sha256:text/plain" \
  "${exe}.asc:application/pgp-signature"

oras pull --oci-layout "${layout}:${version}" --output "${work}/pulled"
cd "${work}/pulled"
sha256sum --check "${exe}.sha256"
gpgv --keyring "${work}/key.gpg" "${exe}.asc" "${exe}"
