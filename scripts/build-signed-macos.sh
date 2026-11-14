#!/usr/bin/env bash
set -euo pipefail

identity="${1:-}"
if [[ ! "$identity" =~ ^[0-9a-fA-F]{40}$ ]]; then
  printf '%s\n' 'Usage: build-signed-macos.sh <Apple Development certificate SHA-1> [repository]' >&2
  exit 2
fi
if [[ "$(uname -s)" != Darwin ]]; then
  printf '%s\n' 'Run this script on macOS with Xcode 27 / Swift 6.4 or newer selected.' >&2
  exit 2
fi
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_path="${2:-$script_dir/..}"
cd "$repo_path"
test -f Sources/Secretive.xcodeproj/project.xcproj
for tool in xcrun security openssl python3 codesign; do command -v "$tool" >/dev/null; done

output_parent="${SECRETIVE_SIGNED_BUILD_ROOT:-$HOME/Library/Developer/Xcode/DerivedData}"
mkdir -p "$output_parent"
artifacts="$(mktemp -d "$output_parent/SecretiveLocal.XXXXXX")"
printf 'Build output: %s\n' "$artifacts"
git rev-parse HEAD | tee "$artifacts/commit.txt"
xcrun xcodebuild -version | tee "$artifacts/xcode-version.txt"
xcrun swift --version | tee "$artifacts/swift-version.txt"

# Read public certificate metadata only. The common-name suffix is not necessarily the Team ID.
team_id="$(python3 - "$identity" "$artifacts/selected-certificate.pem" <<'PY'
import hashlib
from pathlib import Path
import re
import ssl
import subprocess
import sys

identity = sys.argv[1].lower()
identities = subprocess.check_output(['security', 'find-identity', '-v', '-p', 'codesigning'], text=True)
valid = {value.lower() for value in re.findall(r'^\s*\d+\)\s+([0-9A-Fa-f]{40})\s+"', identities, re.MULTILINE)}
if identity not in valid:
    raise SystemExit('The selected certificate is not a valid signing identity with an available private key.')
certificates = subprocess.check_output(['security', 'find-certificate', '-a', '-p'], text=True)
for pem in re.findall(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', certificates, re.DOTALL):
    if hashlib.sha1(ssl.PEM_cert_to_DER_cert(pem)).hexdigest() == identity:
        path = Path(sys.argv[2])
        path.write_text(pem + '\n')
        subject = subprocess.check_output([
            'openssl', 'x509', '-in', str(path), '-noout', '-subject',
            '-nameopt', 'RFC2253,sep_multiline'
        ], text=True)
        if not re.search(r'^\s*CN\s*=\s*Apple Development:', subject, re.MULTILINE):
            raise SystemExit('Select an Apple Development identity for this local Debug build.')
        teams = re.findall(r'^\s*OU\s*=\s*([A-Z0-9]{10})\s*$', subject, re.MULTILINE)
        if len(set(teams)) != 1:
            raise SystemExit('Cannot determine a unique Team ID from the selected certificate OU field.')
        print(teams[0])
        break
else:
    raise SystemExit('The public certificate matching the selected SHA-1 was not found.')
PY
)"

bundle_id="${team_id}.com.example.Secretive"
printf 'Signing Team: %s\nBundle base: %s\n' "$team_id" "$bundle_id"
printf '%s\n' 'Xcode must have access to this Team to manage provisioning profiles.'

# Automatic signing selects an available Apple Development certificate from the selected Team.
xcrun xcodebuild -project Sources/Secretive.xcodeproj -scheme Secretive \
  -configuration Debug -destination 'platform=macOS' -derivedDataPath "$artifacts/DerivedData" \
  -allowProvisioningUpdates \
  DEVELOPMENT_TEAM="$team_id" SECRETIVE_DEVELOPMENT_TEAM_OSS="$team_id" \
  SECRETIVE_BASE_BUNDLE_ID_OSS="$bundle_id" CODE_SIGN_STYLE=Automatic \
  CODE_SIGN_IDENTITY='Apple Development' CODE_SIGNING_ALLOWED=YES CODE_SIGNING_REQUIRED=YES \
  CI_VERSION=0.0.0 CI_BUILD_NUMBER=1 \
  build 2>&1 | tee "$artifacts/app-build.log"

app="$artifacts/DerivedData/Build/Products/Debug/Secretive.app"
codesign --verify --deep --strict --verbose=2 "$app" 2>&1 | tee "$artifacts/signature-verification.log"
codesign -d --verbose=4 "$app" 2> "$artifacts/signature-details.log"
actual_team="$(awk -F= '$1 == "TeamIdentifier" { print $2; exit }' "$artifacts/signature-details.log")"
if [[ "$actual_team" != "$team_id" ]]; then
  printf '%s\n' 'The built app is not signed by the selected Team; inspect signature-details.log.' >&2
  exit 1
fi

printf '\nSigned App: %s\nRun: open %q\n' "$app" "$app"
printf '%s\n' 'Keep the same Team and bundle identifiers for future builds to retain access to your keys.'
