#!/bin/bash
# Detached-sign artifacts in dist/ when an offline release key is available.
# The private key is read only from KER_RELEASE_GNUPGHOME. Nothing in the
# git tree is a secret key, and this script never generates one.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
DIST="$ROOT/dist"
if [ -z "${KER_RELEASE_GNUPGHOME:-}" ]; then
  echo "sign-dist: KER_RELEASE_GNUPGHOME is unset; leaving packages unsigned" >&2
  exit 0
fi
if [ ! -d "$KER_RELEASE_GNUPGHOME" ]; then
  echo "sign-dist: KER_RELEASE_GNUPGHOME is not a directory; leaving packages unsigned" >&2
  exit 0
fi
# Refuse to sign if the caller pointed at a path inside the repository.
case "$KER_RELEASE_GNUPGHOME" in
  "$ROOT"|"$ROOT"/*)
    echo "sign-dist: refusing to use a keyring inside the source tree" >&2
    exit 1
    ;;
esac
if ! gpg --batch --homedir "$KER_RELEASE_GNUPGHOME" --list-secret-keys >/dev/null 2>&1; then
  echo "sign-dist: no secret key in KER_RELEASE_GNUPGHOME; leaving packages unsigned" >&2
  exit 0
fi
shopt -s nullglob
signed=0
for f in "$DIST"/*.deb "$DIST"/*.rpm "$DIST"/*.apk "$DIST"/*.pkg.tar.zst; do
  [ -f "$f" ] || continue
  gpg --batch --yes --homedir "$KER_RELEASE_GNUPGHOME" \
    --detach-sign --output "$f.sig" "$f"
  signed=$((signed + 1))
done
echo "sign-dist: wrote $signed detached signature(s)"
