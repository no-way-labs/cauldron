# Release Checklist

Use this checklist when preparing and publishing a new release.

Releases are managed via GitHub Actions. Pushing a tag triggers the build + release workflow, which also auto-updates the app's Homebrew formula in [homebrew-cauldron](https://github.com/no-way-labs/homebrew-cauldron) (all five apps have formulas; the update step is skipped with a log message if a formula is ever missing).

## Tag Conventions

| App | Tag format | Example |
|-----|-----------|---------|
| mitt | `v*` | `v0.5.0` |
| seance | `seance-v*` | `seance-v0.2.8` |
| familiar | `familiar-v*` | `familiar-v0.1.3` |
| omen | `omen-v*` | `omen-v0.1.0` |
| covenant | `covenant-v*` | `covenant-v0.1.0` |

## Pre-Release

- [ ] Zig **0.16.0** installed (`zig version`) — the build enforces `minimum_zig_version` via build.zig.zon
- [ ] Bump `pub const version` in the app's `main.zig` to match the tag
- [ ] Run tests: `zig build test`
- [ ] Check formatting: `zig fmt --check build.zig build.zig.zon apps`
- [ ] Cross-compile all release targets locally (comptime-gated OS branches are only analyzed for the target being built, so a native-only build can hide Linux breakage):
  ```bash
  zig build -Dtarget=aarch64-macos -Doptimize=ReleaseSafe
  zig build -Dtarget=x86_64-macos -Doptimize=ReleaseSafe
  zig build -Dtarget=x86_64-linux -Doptimize=ReleaseSafe
  zig build -Dtarget=aarch64-linux -Doptimize=ReleaseSafe
  ```
- [ ] Commit all changes to `main` branch and confirm the CI workflow is green

## Release

- [ ] Create and push the git tag (see tag conventions above):
  ```bash
  # Example for omen:
  git tag -a omen-v0.X.Y -m "Release omen-v0.X.Y"
  git push origin omen-v0.X.Y
  ```

- [ ] Wait for GitHub Actions to complete:
  - [ ] Build workflow completes (4 platform binaries)
  - [ ] Release is created with all binaries and SHA256 checksums
  - [ ] Homebrew formula in `homebrew-cauldron` is auto-updated

## Post-Release Verification

- [ ] Verify GitHub Release page has all 4 tar.gz files and checksums
- [ ] Verify Homebrew formula was updated:
  ```bash
  # Check Formula/<app>.rb in homebrew-cauldron
  # Version, URLs, and SHA256s should all match the new release
  ```
- [ ] Test Homebrew installation:
  ```bash
  brew update
  brew upgrade <app>   # mitt, seance, familiar, omen, or covenant
  ```

## If Homebrew Formula Wasn't Updated

The CI needs a `HOMEBREW_TAP_TOKEN` secret (a PAT with repo scope for `homebrew-cauldron`). If the auto-update failed:

1. Download and calculate SHA256s:
   ```bash
   # Replace APP and TAG as needed (e.g., APP=omen TAG=omen-v0.1.0)
   for target in macos-aarch64 macos-x86_64 linux-aarch64 linux-x86_64; do
     curl -sL "https://github.com/no-way-labs/cauldron/releases/download/$TAG/$APP-$target.tar.gz" -o "$APP-$target.tar.gz"
     shasum -a 256 "$APP-$target.tar.gz"
   done
   ```

2. Manually update the formula in `homebrew-cauldron/Formula/<app>.rb`
3. Commit and push to homebrew-cauldron

## Adding a New App

1. Add the tag pattern to `.github/workflows/release.yml` (trigger list, build matrix, and the "Determine app from tag" step)
2. Create `Formula/<app>.rb` in homebrew-cauldron, modeled on an existing formula, pointed at the app's first release with real SHA256s (the workflow's sed-based updater fills subsequent releases automatically)
3. Add the app to the tag table above
