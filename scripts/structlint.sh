#!/usr/bin/env bash
# Structural lint: the rules of the Go standard and of AGENTS.md that a
# compiler or golangci-lint does not check. Usage: structlint.sh [root]
set -euo pipefail

cd "${1:-"$(dirname "$0")/.."}"

failures=0
fail() {
  echo "$1"
  failures=$((failures + 1))
}

mapfile -t files < <(git ls-files --cached --others --exclude-standard | grep -Ev '(^|/)testdata/' | sort)
existing=()
for f in "${files[@]}"; do
  [[ -f "${f}" ]] && existing+=("${f}")
done
files=("${existing[@]}")

select_files() {
  printf '%s\n' "${files[@]}" | grep -E "$1" || true
}

mapfile -t go_files < <(select_files '\.go$')
mapfile -t docs < <(select_files '^(README|AGENTS)\.md$|^docs/[^/]+\.md$')
mapfile -t code < <(select_files '\.(go|sh|ya?ml|toml|json|limits)$|^Makefile$|^go\.mod$|^\.[a-z]+$')

# Module identity and dependencies.
if [[ -f go.mod ]]; then
  grep -qE '^module github\.com/get-sybers/[a-z0-9._/-]+$' go.mod ||
    fail "go.mod: module path is not github.com/get-sybers/<lower-case repo>"
  grep -qE '^go [0-9]+\.[0-9]+\.[0-9]+$' go.mod ||
    fail "go.mod: the go directive has no patch component"
  while IFS=: read -r line text; do
    [[ "${text}" == *github.com/get-sybers/*"=>"* ]] && fail "go.mod:${line}: replace names a sibling module"
    [[ "${text}" == *"//"* ]] || fail "go.mod:${line}: replace carries no reason"
  done < <(grep -n '=>' go.mod || true)
  while IFS=: read -r line _; do
    fail "go.mod:${line}: assertion library"
  done < <(grep -nE 'stretchr/testify|onsi/(gomega|ginkgo)|matryer/is|alecthomas/assert|frankban/quicktest|gotest\.tools' go.mod || true)
else
  fail "go.mod: missing"
fi

# Layout.
[[ -d internal ]] || fail "internal/: missing"
for f in "${go_files[@]}"; do
  if grep -qE '^package main$' "${f}" && [[ ! "${f}" =~ ^cmd/[^/]+/[^/]+\.go$ ]]; then
    fail "${f}: package main outside cmd/<name>/"
  fi
  [[ "${f}" =~ (^|/)(assert|require)/ ]] && fail "${f}: assertion helper package"
done
for f in cmd/*/main.go; do
  [[ -f "${f}" ]] || continue
  lines="$(wc -l <"${f}")"
  ((lines <= 60)) || fail "${f}: ${lines} lines; a command wires and maps exit codes in at most 60"
  while IFS=: read -r line _; do
    fail "${f}:${line}: a command declares only main and run"
  done < <(grep -nE '^(func|type) ' "${f}" | grep -vE '^[0-9]+:func (main|run)\(' || true)
done

# Naming.
for f in "${go_files[@]}"; do
  while IFS=: read -r line _; do
    fail "${f}:${line}: Get-style name; use Read, Load, Check, List, Run, Classify or Detect"
  done < <(grep -nE '^func (\([^)]*\) )?[Gg]et[A-Z0-9_]' "${f}" || true)
done

# One home for everything: no byte-identical files, and every data file is embedded.
if ((${#files[@]} > 0)); then
  while read -r first second; do
    fail "${second}: identical to ${first}"
  done < <(find "${files[@]}" -maxdepth 0 -type f -size +0 ! -name '*.golden' -exec sha256sum {} + |
    sort | awk 'seen[$1] {print seen[$1], $2; next} {seen[$1] = $2}')
fi
while read -r f; do
  [[ -n "${f}" ]] || continue
  grep -qE "^//go:embed .*\\b$(basename "${f}")\\b" "$(dirname "${f}")"/*.go 2>/dev/null ||
    fail "${f}: data file is not embedded by its package"
done < <(select_files '^(internal|cmd)/.*\.json$')

# Repository hygiene.
for f in README.md CHANGELOG.md AGENTS.md Makefile .gitignore .golangci.yml; do
  [[ -f "${f}" ]] || fail "${f}: missing"
done
if [[ -f Makefile ]]; then
  for target in build test vet fmt fmt-check tidy generate conform upgrade; do
    grep -qE "^${target}:" Makefile || fail "Makefile: no ${target} target"
  done
fi
if [[ -f CHANGELOG.md ]]; then
  grep -qE '^## \[Unreleased\]' CHANGELOG.md || fail "CHANGELOG.md: no ## [Unreleased] section"
fi

# Changes are tracked in the changelog only. The words are split so this
# file does not match itself.
markers="TO""DO|FIX""ME|X""XX|HA""CK"
# shellcheck disable=SC2016 # the backticks are literal: code spans are exempt
strip_code='s/`[^`]*`//g'
for f in "${code[@]}" "${docs[@]}"; do
  while IFS=: read -r line _; do
    fail "${f}:${line}: tracking marker; record changes in CHANGELOG.md"
  done < <(sed -E "${strip_code}" "${f}" | grep -nE "(^|[^[:alnum:]_.])(${markers})([^[:alnum:]_(]|\$)" || true)
done

# Docs state what the repository does now. Fenced blocks and code spans are exempt.
tracking='will|roadmap|tbd|wip|not yet|coming soon|planned|in progress|future work|to be (added|done|decided)'
for f in "${docs[@]}"; do
  while IFS=: read -r line _; do
    fail "${f}:${line}: plan or status wording; docs state fact"
  done < <(awk '/^```/ {fenced = !fenced; print ""; next} {print fenced ? "" : $0}' "${f}" |
    sed -E "${strip_code}" | grep -niE "(^|[^[:alnum:]])(${tracking})([^[:alnum:]]|\$)|^[[:space:]]*[-*] \[[ xX]\]" || true)
done

# Comments are minimal: no run of more than three full-line comments.
# Directives and the shebang do not count.
for f in $(select_files '\.(go|sh|ya?ml)$|^Makefile$'); do
  comment='^[[:space:]]*#'
  directive='^[[:space:]]*#(!|[[:space:]]*(shellcheck|yamllint) )'
  if [[ "${f}" == *.go ]]; then
    comment='^[[:space:]]*//'
    directive='^[[:space:]]*//(go:|nolint|line |export )'
  fi
  while read -r line; do
    fail "${f}:${line}: comment block longer than three lines"
  done < <(awk -v comment="${comment}" -v directive="${directive}" '
    $0 ~ comment && $0 !~ directive { run++; if (run == 4) print NR; next }
    $0 ~ directive { next }
    { run = 0 }' "${f}")
done

if ((failures > 0)); then
  echo "structlint: ${failures} failure(s)"
  exit 1
fi
