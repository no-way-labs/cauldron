# Release Checklist

Use this checklist when preparing and publishing a new release.

## Pre-Release

- [ ] Update version number in relevant files:
  - [ ] `build.zig` - Check if version is tracked here
  - [ ] `README.md` - Update any version references
  - [ ] Any other version references in documentation

- [ ] Update `CHANGELOG.md` with release notes
  - [ ] List new features
  - [ ] List bug fixes
  - [ ] List breaking changes (if any)
  - [ ] Add release date

- [ ] Test the build locally for all targets:
  ```bash
  zig build -Dtarget=aarch64-macos -Doptimize=ReleaseSafe
  zig build -Dtarget=x86_64-macos -Doptimize=ReleaseSafe
  zig build -Dtarget=x86_64-linux -Doptimize=ReleaseSafe
  zig build -Dtarget=aarch64-linux -Doptimize=ReleaseSafe
  ```

- [ ] Run tests: `zig build test`

- [ ] Commit all changes to `main` branch

## Release

- [ ] Create and push git tag:
  ```bash
  git tag -a v0.X.Y -m "Release v0.X.Y"
  git push origin v0.X.Y
  ```

- [ ] Wait for GitHub Actions to complete:
  - [ ] Build workflow completes
  - [ ] Release is created with all 4 platform binaries
  - [ ] Release notes are populated

## Post-Release Verification

- [ ] Verify GitHub Release at https://github.com/no-way-labs/cauldron/releases/latest
  - [ ] All 4 tar.gz files are present (macOS arm64/x86_64, Linux arm64/x86_64)
  - [ ] SHA256 checksums are in release notes
  - [ ] Release notes are correct

- [ ] Verify Homebrew formula was updated automatically:
  - [ ] Check `Formula/mitt.rb` on main branch
  - [ ] Version number matches release (e.g., `version "0.X.Y"`)
  - [ ] All 4 URLs point to new release tag (e.g., `.../download/v0.X.Y/...`)
  - [ ] All 4 SHA256 checksums are updated and match the release

- [ ] Test Homebrew installation:
  ```bash
  brew update
  brew upgrade mitt
  # Or for fresh install:
  brew uninstall mitt
  brew install mitt
  mitt --version  # Should show new version
  ```

## If Homebrew Formula Wasn't Updated Correctly

If the GitHub Actions workflow failed to update the formula:

1. Download and calculate SHA256s:
   ```bash
   cd /tmp
   curl -sL https://github.com/no-way-labs/cauldron/releases/download/v0.X.Y/mitt-macos-aarch64.tar.gz -o mitt-macos-aarch64.tar.gz
   shasum -a 256 mitt-macos-aarch64.tar.gz

   curl -sL https://github.com/no-way-labs/cauldron/releases/download/v0.X.Y/mitt-macos-x86_64.tar.gz -o mitt-macos-x86_64.tar.gz
   shasum -a 256 mitt-macos-x86_64.tar.gz

   curl -sL https://github.com/no-way-labs/cauldron/releases/download/v0.X.Y/mitt-linux-aarch64.tar.gz -o mitt-linux-aarch64.tar.gz
   shasum -a 256 mitt-linux-aarch64.tar.gz

   curl -sL https://github.com/no-way-labs/cauldron/releases/download/v0.X.Y/mitt-linux-x86_64.tar.gz -o mitt-linux-x86_64.tar.gz
   shasum -a 256 mitt-linux-x86_64.tar.gz
   ```

2. Manually update `Formula/mitt.rb`:
   - Update `version "0.X.Y"`
   - Update all URLs to point to `v0.X.Y`
   - Update all SHA256 checksums with values from step 1

3. Commit and push:
   ```bash
   git add Formula/mitt.rb
   git commit -m "Update Homebrew formula for v0.X.Y"
   git push origin main
   ```

## Troubleshooting

### Workflow Failures

- Check GitHub Actions logs at https://github.com/no-way-labs/cauldron/actions
- Common issues:
  - Build failures: Check Zig version compatibility
  - Permission errors: Verify `GITHUB_TOKEN` has write permissions
  - Formula update failures: Check sed commands in `.github/workflows/release.yml`

### Homebrew Installation Issues

- Users seeing old version:
  ```bash
  brew update  # Updates tap metadata
  brew upgrade mitt
  ```

- Formula not found:
  ```bash
  brew untap no-way-labs/cauldron
  brew tap no-way-labs/cauldron
  brew install mitt
  ```
