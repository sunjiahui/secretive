#!/usr/bin/env bash
set -euo pipefail

repo_path="${1:-.}"
cd "$repo_path"
if [[ "$(uname -s)" != Darwin ]]; then
  printf '%s\n' 'Run this script on macOS with Xcode 27 / Swift 6.4 or newer selected.' >&2
  exit 2
fi
command -v xcrun >/dev/null
test -f Sources/Secretive.xcodeproj/project.xcproj

artifacts="$(mktemp -d "${TMPDIR:-/tmp}/secretive-build.XXXXXX")"
printf 'Build output: %s\n' "$artifacts"
git rev-parse HEAD | tee "$artifacts/commit.txt"
xcrun xcodebuild -version | tee "$artifacts/xcode-version.txt"
xcrun swift --version | tee "$artifacts/swift-version.txt"
xcode_major="$(awk 'NR == 1 { split($2, v, "."); print v[1] }' "$artifacts/xcode-version.txt")"
swift_version="$(cat "$artifacts/swift-version.txt")"
if [[ ! "$xcode_major" =~ ^[0-9]+$ ]] || (( xcode_major < 27 )); then
  printf '%s\n' 'This source uses the Xcode 27 JSON project format; select Xcode 27 or newer.' >&2
  exit 2
fi
if [[ "$swift_version" =~ Swift\ version\ ([0-9]+)\.([0-9]+) ]]; then
  swift_major="${BASH_REMATCH[1]}"
  swift_minor="${BASH_REMATCH[2]}"
else
  printf '%s\n' 'Cannot determine the selected Swift version.' >&2
  exit 2
fi
if (( swift_major < 6 || (swift_major == 6 && swift_minor < 4) )); then
  printf '%s\n' 'Sources/Packages requires Swift tools 6.4 or newer.' >&2
  exit 2
fi

xcrun xcodebuild -project Sources/Secretive.xcodeproj -scheme PackageTests \
  -destination 'platform=macOS' -derivedDataPath "$artifacts/DerivedData" \
  -resultBundlePath "$artifacts/PackageTests.xcresult" \
  test CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO 2>&1 | tee "$artifacts/package-tests.log"
xcrun swift test --build-system swiftbuild --scratch-path "$artifacts/RootPackages" \
  2>&1 | tee "$artifacts/root-tests.log"
xcrun xcodebuild -project Sources/Secretive.xcodeproj -scheme Secretive \
  -configuration Debug -destination 'platform=macOS' -derivedDataPath "$artifacts/DerivedData" \
  build CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO 2>&1 | tee "$artifacts/app-build.log"

printf '\nTests and compilation completed. App: %s/DerivedData/Build/Products/Debug/Secretive.app\n' "$artifacts"
printf '%s\n' 'This unsigned build does not verify installed Keychain access, Touch ID, or Secure Enclave behavior.'
