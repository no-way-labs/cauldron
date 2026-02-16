# Release Checklist

Use this checklist when preparing and publishing a new release.

Releases are managed via GitHub Actions. Pushing a tag triggers the build + release workflow, which also auto-updates the Homebrew formula in [homebrew-cauldron](https://github.com/no-way-labs/homebrew-cauldron).

## Tag Conventions

| App | Tag format | Example |
|-----|-----------|---------|
| mitt | `v*` | `v0.5.0` |
| seance | `seance-v*` | `seance-v0.2.0` |

## Pre-Release

- [ ] Run tests: `zig build test`
- [ ] Test the build locally:
  ```bash
  zig build -Dtarget=aarch64-macos -Doptimize=ReleaseSafe
  zig build -Dtarget=x86_64-macos -Doptimize=ReleaseSafe
  zig build -Dtarget=x86_64-linux -Doptimize=ReleaseSafe
  zig build -Dtarget=aarch64-linux -Doptimize=ReleaseSafe
  ```
- [ ] Commit all changes to `main` branch

## Release

- [ ] Create and push git tag:
  ```bash
  # For mitt:
  git tag -a v0.X.Y -m "Release v0.X.Y"
  git push origin v0.X.Y

  # For seance:
  git tag -a seance-v0.X.Y -m "Release seance-v0.X.Y"
  git push origin seance-v0.X.Y
  ```

- [ ] Wait for GitHub Actions to complete:
  - [ ] Build workflow completes (4 platform binaries)
  - [ ] Release is created with all binaries and SHA256 checksums
  - [ ] Homebrew formula in `homebrew-cauldron` is auto-updated

## Post-Release Verification

- [ ] Verify GitHub Release page has all 4 tar.gz files and checksums
- [ ] Verify Homebrew formula was updated:
  ```bash
  # Check the formula in homebrew-cauldron repo
  # Version, URLs, and SHA256s should all match the new release
  ```
- [ ] Test Homebrew installation:
  ```bash
  brew update
  brew upgrade mitt   # or: brew upgrade seance
  ```

## If Homebrew Formula Wasn't Updated

The CI needs a `HOMEBREW_TAP_TOKEN` secret (a PAT with repo scope for `homebrew-cauldron`). If the auto-update failed:

1. Download and calculate SHA256s:
   ```bash
   # Replace APP and TAG as needed (e.g., APP=mitt TAG=v0.5.0)
   for target in macos-aarch64 macos-x86_64 linux-aarch64 linux-x86_64; do
     curl -sL "https://github.com/no-way-labs/cauldron/releases/download/$TAG/$APP-$target.tar.gz" -o "$APP-$target.tar.gz"
     shasum -a 256 "$APP-$target.tar.gz"
   done
   ```

2. Manually update the formula in `homebrew-cauldron/Formula/<app>.rb`
3. Commit and push to homebrew-cauldron
