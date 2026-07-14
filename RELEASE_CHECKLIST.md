# Release checklist

Pushing an app tag runs `.github/workflows/release.yml`, which validates the
tag, injects its bare semantic version into the binary, builds four static
archives, publishes SHA-256 sidecars, and updates the corresponding formula in
[`homebrew-cauldron`](https://github.com/no-way-labs/homebrew-cauldron).

## Tag conventions

| App | Tag format | Next Go-port line |
|---|---|---|
| mitt | `vMAJOR.MINOR.PATCH` | `v0.5.x` |
| seance | `seance-vMAJOR.MINOR.PATCH` | `seance-v0.3.x` |
| familiar | `familiar-vMAJOR.MINOR.PATCH` | `familiar-v0.3.x` |
| omen | `omen-vMAJOR.MINOR.PATCH` | `omen-v0.2.x` |
| covenant | `covenant-vMAJOR.MINOR.PATCH` | `covenant-v0.2.x` |

Tags must contain exactly three numeric components. Published tags are
immutable: never move or reuse one.

## Before tagging

- [ ] Install the Go version selected by `go.mod` (Go 1.26 or newer).
- [ ] Review `CHANGELOG.md`, `README.md`, and `SECURITY.md` for the app's actual
  behavior and known limitations.
- [ ] Obtain and record the repository owner's license decision: the tracked
  GPLv3 `LICENSE` conflicts with the historical MIT README and Homebrew
  formulas. Update all locations consistently; do not infer the answer in
  release automation.
- [ ] If the Go toolchain or runtime module versions changed, update
  `THIRD_PARTY_NOTICES` from their pinned upstream `LICENSE`/`PATENTS` files.
- [ ] Confirm formatting and analysis:

  ```bash
  test -z "$(gofmt -l .)"
  go vet ./...
  go tool staticcheck ./...
  go tool govulncheck ./...
  ```

- [ ] Run the complete race suite and build every package:

  ```bash
  go test -race ./...
  go build ./...
  ```

- [ ] Cross-compile the app for all release targets. Replace `APP` and
  `VERSION`; the version is injected at link time and is not edited in source:

  ```bash
  APP=omen
  VERSION=0.2.0
  mkdir -p dist
  for target in darwin/arm64 darwin/amd64 linux/arm64 linux/amd64; do
    GOOS=${target%/*} GOARCH=${target#*/} CGO_ENABLED=0 \
      go build -trimpath -ldflags "-s -w -X main.version=$VERSION" \
      -o "dist/$APP-${target%/*}-${target#*/}" "./cmd/$APP"
  done
  ./dist/$APP-linux-amd64 --version
  ```

- [ ] Inspect the app's actual Homebrew `test do` block in the external tap and
  run the same assertions against the release candidate.
- [ ] Before a seance tag, exercise the interactive editor on macOS Terminal
  and a Linux terminal: arrows, Home/End, Delete/Backspace, Ctrl+U/A/E, Ctrl+C,
  resize/redraw, and terminal restoration after exit.
- [ ] Confirm CI is green on `main` and the working tree contains the intended
  changes only.

## Publish

- [ ] Create and push an annotated immutable tag:

  ```bash
  git tag -a omen-v0.2.0 -m "Release omen-v0.2.0"
  git push origin omen-v0.2.0
  ```

- [ ] Confirm the release workflow selected the correct app and bare version.
- [ ] Confirm exactly four archives and four sidecars were uploaded, preserving
  these spellings:

  ```text
  <app>-macos-aarch64.tar.gz
  <app>-macos-x86_64.tar.gz
  <app>-linux-aarch64.tar.gz
  <app>-linux-x86_64.tar.gz
  ```

- [ ] Inspect an archive and confirm it contains the app binary, `LICENSE`, and
  `THIRD_PARTY_NOTICES`.

- [ ] Confirm the release notes contain the same SHA-256 values as the sidecars.
- [ ] Confirm the matching Homebrew formula's version, URLs, all four hashes,
  and owner-approved license metadata were updated and pushed. For Omen, also
  confirm its description no longer claims anonymous voting.

`workflow_dispatch` accepts an existing tag for retrying the workflow. It still
checks out that immutable tag; it must not be used to release arbitrary branch
state.

## Post-release verification

- [ ] Download one archive independently and verify its checksum.
- [ ] Run `<app> --version` and a representative local-only flow.
- [ ] Test the formula:

  ```bash
  brew update
  brew upgrade <app>
  brew test <app>
  ```

- [ ] For protocol apps, run a compatibility smoke test with the previous
  release where the v1 protocol promises interoperation.

## Formula recovery

The workflow needs `HOMEBREW_TAP_TOKEN` with write access to the tap. If formula
automation fails, calculate the four archive hashes from the immutable release,
update `Formula/<app>.rb` manually, run `brew audit --strict <app>` and
`brew test <app>`, then commit the tap change.

## Rollback

Do not move the bad tag. Revert or fix the source and publish a new patch-version
tag. Release and formula URLs must always continue to identify immutable bytes.
