#!/usr/bin/env bash
# Build the app-powerd RPM from the current checkout.
# Usage: packaging/rpm/build.sh [RELEASE]   (RELEASE defaults to 1)
# Output: dist-rpm/*.rpm
set -euo pipefail

release="${1:-1}"
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"

version="$(sed -n '/^\[workspace\.package\]/,/^\[/s/^version *= *"\(.*\)"/\1/p' Cargo.toml)"
[ -n "$version" ] || { echo "could not read workspace version" >&2; exit 1; }

topdir="$(mktemp -d)"
trap 'rm -rf "$topdir"' EXIT
mkdir -p "$topdir/SOURCES"

git -c safe.directory="$root" archive --format=tar.gz \
  --prefix="app-powerd-$version/" -o "$topdir/SOURCES/app-powerd-$version.tar.gz" HEAD

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$root/target}"

rpmbuild -bb packaging/rpm/app-powerd.spec \
  --define "_topdir $topdir" \
  --define "pkg_version $version" \
  --define "pkg_release $release"

mkdir -p dist-rpm
find "$topdir/RPMS" -name '*.rpm' -exec cp -v {} dist-rpm/ \;
