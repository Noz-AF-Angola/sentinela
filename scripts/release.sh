#!/usr/bin/env bash
# Builds the signed release files that instalar.sh downloads:
#   sentinela-linux-amd64, sentinela-linux-arm64, instalar.sh, VERSION, SHA256SUMS, SHA256SUMS.asc
#
#   scripts/release.sh 0.2.0            build and sign into dist/v0.2.0/
#   scripts/release.sh 0.2.0 --upload   also attach them to the GitHub release v0.2.0 (gh CLI)
#
# The signature is made with the release key (fingerprint below), which only the maintainer holds.
# instalar.sh refuses any SHA256SUMS that this key did not sign.
set -euo pipefail

FPR=54936EE1C78351E9FE4929A02206DA328A608A83
VERSION=${1:?usage: scripts/release.sh X.Y.Z [--upload]}
VERSION=${VERSION#v}
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "version must be X.Y.Z" >&2; exit 2; }

cd "$(dirname "$0")/.."
OUT=dist/v$VERSION
rm -rf "$OUT"
mkdir -p "$OUT"

for arch in amd64 arm64; do
	CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -buildvcs=false \
		-ldflags "-s -w -X main.version=$VERSION" -o "$OUT/sentinela-linux-$arch" ./cmd/sentinela
done
install -m 0755 instalar.sh "$OUT/instalar.sh"
printf '%s\n' "$VERSION" >"$OUT/VERSION"

(cd "$OUT" && shasum -a 256 sentinela-linux-amd64 sentinela-linux-arm64 instalar.sh VERSION >SHA256SUMS)
gpg --batch --yes --local-user "$FPR" --armor --detach-sign --output "$OUT/SHA256SUMS.asc" "$OUT/SHA256SUMS"
gpg --verify "$OUT/SHA256SUMS.asc" "$OUT/SHA256SUMS"
cat "$OUT/SHA256SUMS"

if [ "${2:-}" = --upload ]; then
	gh release upload "v$VERSION" "$OUT"/* --clobber
fi
