# Conformance

One sentence governs the rest: **a change is ready when `make conform` is green, and CI runs the
same command.**

## 1. The gate

`make conform` runs these in order and stops at the first failure.

| Target | Runs | Catches |
| --- | --- | --- |
| `fmt-check` | `gofmt -l` from the module's toolchain; `golangci-lint fmt --diff` | unformatted code, mis-grouped imports |
| `vet` | `go vet -tags integration ./...` | suspicious constructs, including the integration test |
| `build` | `go build -o bin/slopmop ./cmd/slopmop` | a broken build |
| `test` | `go test -count=1 -shuffle=on -cover ./...` | failing or order-dependent tests |
| `integration` | `go test -count=1 -tags integration ./cmd/...` | the built binary, driven through `os/exec` |
| `tidy-check` | `go mod tidy -diff` | drift in `go.mod` or `go.sum` |
| `generate-check` | `go generate ./...`, then compares the tree | stale generated files |
| `cross` | `go build ./...` for windows/amd64, windows/arm64, darwin/amd64, darwin/arm64, linux/arm64 | a platform-specific break |
| `structlint` | `scripts/structlint.sh` | the structural rules of section 3 |
| `structlint-test` | the structural lint over `scripts/testdata/structlint/tree` | a lint that stops reporting; the output must equal `expected.txt` |
| `lint` | `golangci-lint config verify`, `golangci-lint run` | the linters of `.golangci.yml` |

The build runs with `CGO_ENABLED=0` and `GOWORK=off`.

## 2. Other targets

| Target | Does |
| --- | --- |
| `fmt` | formats the code |
| `tidy` | runs `go mod tidy` |
| `generate` | runs `go generate ./...` |
| `golden-update` | rewrites the golden files of every package whose tests use `internal/golden` |
| `tools` | builds the pinned golangci-lint into `.cache/bin` |
| `vuln` | runs govulncheck at its latest version; it needs the network and is a CI job of its own |
| `upgrade` | raises the Go directive and every dependency, then runs the gate |
| `clean` | removes `bin` and `.cache` |

## 3. Structural lint

`scripts/structlint.sh` checks what a compiler and golangci-lint do not.

- The module path is `github.com/get-sybers/<lower-case repo>` and the `go` directive has a patch component.
- A `replace` carries a reason and never names a sibling module. No assertion library is required.
- `package main` lives only under `cmd/<name>/`; `cmd/<name>/main.go` declares only `main` and `run` in at most 60 lines.
- No function is named `Get...` or `get...`.
- No two files are byte-identical. Every JSON data file under `internal/` or `cmd/` is embedded by its package.
- `LICENSE` is the MIT licence and `README.md` declares the same identifier.
- `LICENSE`, `README.md`, `CHANGELOG.md`, `AGENTS.md`, `Makefile`, `.gitignore` and `.golangci.yml` exist; the Makefile has the uniform targets; the changelog has `## [Unreleased]`.
- No tracking marker stands in code, scripts, configuration or docs.
- `README.md`, `AGENTS.md` and `docs/*.md` hold no plan or status wording and no tick boxes. Fenced blocks and code spans are exempt.
- No run of more than three full-line comments stands in Go, shell, YAML or the Makefile.

Paths under a `testdata` directory are exempt from every check.

## 4. Version pins

| Pin | Lives in |
| --- | --- |
| Go | the `go` directive of `go.mod` |
| Dependencies | `go.mod` and `go.sum` |
| golangci-lint and the hooks | the `rev` of each entry in `.pre-commit-config.yaml` |
| GitHub Actions | the commit SHA and version comment on each `uses:` line |
| oras | `ORAS_VERSION` and `ORAS_SHA256`, the checksum of its download, in `.github/workflows/release.yml` |
| Version ceilings | `upgrade.limits` |

`scripts/tools.sh` reads the golangci-lint version from `.pre-commit-config.yaml` and builds it with
the module's Go version, because the linter refuses a module newer than the Go that built it. It
rebuilds when either version changes.

## 5. CI

`.github/workflows/ci.yml` runs on pull requests, on pushes to `main`, weekly and on demand, with
read-only permissions.

| Job | Runs |
| --- | --- |
| `conform` | `make conform` |
| `vuln` | `make vuln` |
| `platform` | on Windows and macOS: `go test -count=1 -shuffle=on ./...`, then the integration test, which builds the binary and drives it through `os/exec` |
| `all_green` | fails when any job failed or was cancelled; the one status check a branch rule requires |

`conform` runs on Linux. `platform` runs no lint: it shows that the tests pass and the binary runs
on the other two operating systems.

Dependabot raises the GitHub Actions and Go module pins weekly, seven days after a release.

## 6. Upgrade

`make upgrade` moves the `go` directive and every dependency to the newest version, re-applies each
ceiling in `upgrade.limits`, runs `go mod tidy`, then runs the gate. When the gate fails, `go.mod`
and `go.sum` are restored.

## 7. Release

`.github/workflows/release.yml` is run by hand. It builds the Windows binary from any branch and
keeps it with the run for 14 days; run with `publish` on `main`, it publishes that build as a
package on the GitHub Container Registry, `ghcr.io/get-sybers/slopmop:v<version>`. It makes no
GitHub release.

- The version is never an input: it is the newest `## [X.Y.Z]` of `CHANGELOG.md`, raised in the pull
  request that cuts the release. A build that is not a publish is `v0.0.0`, which is no release.
- A version is published once. A publish stops when the tag of the version is there already: when
  the run begins, and again before the build is signed.
- The `build` job runs on Windows with a token that reads: the tests, the integration test, then
  `go build -trimpath -buildvcs=true` for windows/amd64. When the binary is built the checkout is
  as it was checked out, and tagged with the version; the tag is the checkout's alone until the
  version is published.
- Go stamps the binary from git, and `go version -m` shows the stamp: the version, the commit and
  `vcs.modified=false`. The job stops when the stamp of the built file says otherwise. A clone of
  the tag, built with the same Go and the same command, gives the same file. Go takes the version
  from the tag while the module is of `v0` or `v1`: from `v2` on, the path of the module ends in
  the major version.
- The job runs the built file against the PowerShell fixture, writes its `.sha256` and keeps the
  two with the run.
- `scripts/package.sh` signs the binary with the secret key of the keyring, a detached signature
  in `.asc`, and packs the binary, its checksum and its signature with `oras` as one OCI artifact.
  A file is a layer under its own name, so `oras pull` writes the three files. The script pulls
  the artifact back and stops unless the checksum holds and the public key it is given, with no
  other key at hand, verifies the signature.
- The `package` job runs the script in every run, with a key made for the run: a pull request
  shows that the package gives the binary out again.
- The `publish` job is the one job with a token that writes. It runs in the `release` environment,
  where a required reviewer approves it when the repository settings name one, and it takes its
  secrets from that environment: `GPG_PRIVATE_KEY`, with `GPG_PASSPHRASE` when the key has one, and
  `GHCR_TOKEN`, the token it pushes to the registry with.
- The publish signs and packs with the key of the environment and verifies with `release-key.asc`,
  the public key the repository gives out. It stops when the repository has no such file, and when
  the key of the environment is not that key.
- The publish attests the provenance of the binary, pushes the package and tags the commit with
  the version. A version that is in the registry with the same binary is left as it is and the
  commit is tagged: the run before stopped between the two. One that is there with another binary
  stops the publish.
- GitHub makes a package private when it is first pushed. Its settings make it public, once, and
  `oras pull` then needs no login.

A pull request that changes the workflow or the script runs the `build` and `package` jobs.
