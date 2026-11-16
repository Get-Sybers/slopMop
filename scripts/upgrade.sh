#!/usr/bin/env bash
# Raises the Go directive and every dependency to its ceiling, then runs the
# gate. The ceilings live in upgrade.limits; a failed gate restores go.mod.
set -euo pipefail

cd "$(dirname "$0")/.."

limit() {
  awk -v module="$1" '$1 == module {print $2}' upgrade.limits
}

restore() {
  git checkout -- go.mod
  if git ls-files --error-unmatch go.sum >/dev/null 2>&1; then
    git checkout -- go.sum
  else
    rm -f go.sum
  fi
}

go_limit="$(limit go)"
go get "go@${go_limit:-latest}"
go get -u -t ./...
while read -r module version _; do
  if [[ -n "${module}" && "${module}" != \#* && "${module}" != go ]]; then
    go get "${module}@${version}"
  fi
done <upgrade.limits
go mod tidy

if ! make conform; then
  restore
  echo "upgrade: the gate failed; go.mod and go.sum are restored" >&2
  exit 1
fi
