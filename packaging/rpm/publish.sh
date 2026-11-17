#!/usr/bin/env bash
# Upload built RPMs.
# Usage: RPM_REPO_TOKEN=... packaging/rpm/publish.sh ARTIFACT_DIR
set -euo pipefail

base="${RPM_REPO_URL:-https://repo.hallb.me}"
dir="${1:?artifact directory required}"
: "${RPM_REPO_TOKEN:?RPM_REPO_TOKEN is not set}"

shopt -s nullglob
uploaded=0 skipped=0
for build in "$dir"/*/; do
  read -r -a targets < "$build/targets.txt"
  for rpm in "$build"*.rpm; do
    name="$(basename "$rpm")"
    arch="${name%.rpm}"; arch="${arch##*.}"   # name-ver-rel.ARCH.rpm
    for target in "${targets[@]}"; do
      path="$target/$arch/$name"
      code="$(curl -s -o /dev/null -w '%{http_code}' -I "$base/$path")"
      if [ "$code" = 200 ]; then
        echo "skip   $path (already published)"
        skipped=$((skipped + 1))
        continue
      fi
      echo "upload $path"
      curl -sSf --retry 3 -X PUT \
        -H "Authorization: Bearer $RPM_REPO_TOKEN" \
        -H "Content-Type: application/x-rpm" \
        --data-binary "@$rpm" \
        "$base/upload/$path"
      echo
      uploaded=$((uploaded + 1))
    done
  done
done
echo "uploaded=$uploaded skipped=$skipped"
[ $((uploaded + skipped)) -gt 0 ] || { echo "no RPMs found under $dir" >&2; exit 1; }
