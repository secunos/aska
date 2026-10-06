#!/bin/sh
# Release pipeline (Client Design §9, OPS-02/OPS-03; Prototype Plan M7).
#
#   scripts/release.sh <tag>            build + package a release candidate for <tag>
#   scripts/release.sh <tag> --sign     sign the candidate's hash lists with the release key
#   scripts/release.sh <tag> --rekor    record the signatures in the Rekor transparency log
#
# The build step runs anywhere with the pinned toolchain; the reference environment is the
# Debian 13 container in release/Dockerfile (the oldest supported glibc, so the dynamically
# linked GUI runs on every supported platform). Set RELEASE_CONTAINER=1 to run the build step
# inside that container automatically (needs docker or podman).
#
# What a release carries (Client Design §9.4): the binaries embed the project's minisign
# PUBLIC key (release/aska-release.pub) and the tag; the tarball carries SHA256SUMS (hashes of
# the binaries) and SHA256SUMS.minisig (its signature); the tarball itself gets a detached
# signature; the Rekor entry for the tarball signature is published in the release notes
# (it cannot be embedded in a binary it covers). `aska verify` checks the first two offline.
#
# Signing happens where the SECRET key lives (never in CI, never in the container):
#   ASKA_RELEASE_SECKEY=~/.minisign/aska-release.key scripts/release.sh v0.1.0-alpha --sign
# The secret key is encrypted by minisign; the passphrase is asked interactively.
set -eu
cd "$(dirname "$0")/.."

TAG="${1:?usage: scripts/release.sh <tag> [--sign|--rekor]}"
MODE="${2:-build}"; MODE="${MODE#--}"
VERSION="${TAG#v}"
OUT="dist/release/$TAG"
PUBFILE="release/aska-release.pub"
NAME="aska-gui-$VERSION-linux-x86_64"

if [ ! -f "$PUBFILE" ]; then
  echo "release.sh: $PUBFILE missing — generate the release key pair first (docs/RELEASING.md §2)" >&2
  exit 1
fi
PUBKEY="$(sed -n 2p "$PUBFILE")"
KEYID="$(sed -n '1s/.*key //p' "$PUBFILE")"

case "$MODE" in
build)
  if [ "${RELEASE_CONTAINER:-0}" = "1" ]; then
    RT="$(command -v podman || command -v docker)"
    "$RT" build -t aska-release release/
    # The checkout belongs to the calling user while git in the container runs as root; git
    # refuses such a repository ("dubious ownership") unless /src is declared safe.
    exec "$RT" run --rm -v "$PWD":/src -w /src -e SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-}" \
      -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0=/src \
      aska-release scripts/release.sh "$TAG"
  fi
  # 0. Prerequisites that silently produced an unreproducible alpha when missing (1 Oct 2026):
  #    git (tag check, clean-tree check, SOURCE_DATE_EPOCH) and the pinned toolchain.
  command -v git >/dev/null || { echo "release.sh: git is required (sudo apt install git)" >&2; exit 1; }
  if ! GIT_ERR="$(git rev-parse --is-inside-work-tree 2>&1 >/dev/null)"; then
    echo "release.sh: git does not accept this directory as a checkout:" >&2
    echo "  $GIT_ERR" | head -3 >&2
    echo "  (no .git: clone the repository; \"dubious ownership\": run as the files' owner or set safe.directory)" >&2
    exit 1
  fi
  WANT="$(sed -n 's/^channel = "\(.*\)"/\1/p' rust-toolchain.toml)"
  HAVE="$(rustc --version | awk '{print $2}')"
  [ "$HAVE" = "$WANT" ] || { echo "release.sh: rustc $HAVE but rust-toolchain.toml pins $WANT (run: rustup toolchain install $WANT)" >&2; exit 1; }
  # 1. The tree must be exactly the tag (or a clean tree, for a candidate without a tag).
  if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null 2>&1; then
    if [ "$(git rev-parse HEAD)" != "$(git rev-parse "$TAG^{commit}")" ]; then
      echo "release.sh: HEAD is not $TAG" >&2; exit 1
    fi
  else
    echo "release.sh: note — tag $TAG does not exist yet; building a candidate from HEAD"
  fi
  if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    echo "release.sh: working tree is not clean" >&2; exit 1
  fi
  export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --pretty=%ct)}"
  case "$SOURCE_DATE_EPOCH" in ''|*[!0-9]*) echo "release.sh: SOURCE_DATE_EPOCH is not a number ('$SOURCE_DATE_EPOCH')" >&2; exit 1;; esac
  # 2. Reproducibility gate for the static binaries.
  scripts/repro-build.sh >/dev/null
  scripts/repro-build.sh --compare | grep "REPRODUCIBLE: OK" || { echo "release.sh: reproducibility gate failed" >&2; exit 1; }
  # 3. Package with the release key and tag embedded (version from the tag).
  rm -rf "$OUT" && mkdir -p "$OUT"
  ASKA_NO_TAR=1 ASKA_RELEASE_PUBKEY="$PUBKEY" ASKA_RELEASE_TAG="$TAG" scripts/package-gui.sh "$VERSION" "" >/dev/null
  cp -r "dist/$NAME" "$OUT/"
  # The static relay for operators, from the repro build.
  TARGET="$(rustc -vV | sed -n 's/^host: //p')"
  cp "target-repro/$TARGET/release/aska-drop" "$OUT/aska-drop-$VERSION-linux-x86_64"
  # The operator's deployment files (installer, torrc, unit, the operator guide), deterministic.
  rm -rf "$OUT/deploy-tmp" && mkdir -p "$OUT/deploy-tmp/aska-drop-deploy-$VERSION"
  cp deploy/install-debian.sh deploy/torrc.aska-drop deploy/aska-drop.service docs/RELAY_OPERATOR_GUIDE.md \
     "$OUT/deploy-tmp/aska-drop-deploy-$VERSION/"
  ( cd "$OUT/deploy-tmp" && tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
      -cf - "aska-drop-deploy-$VERSION" | gzip -n > "../aska-drop-deploy-$VERSION.tar.gz" )
  rm -rf "$OUT/deploy-tmp"
  cat > "$OUT/RELEASE-NOTES.txt" <<TXT
Aska $TAG — release candidate built $(date -u +%Y-%m-%dT%H:%M:%SZ) from commit $(git rev-parse --short HEAD)
Toolchain: $(rustc --version); SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH
Dependencies: $(scripts/vendor-hash.sh 2>/dev/null || echo "VENDOR-HASH: (cargo vendor failed — no network?)")
Release key id: $KEYID  (public key: $PUBKEY)

Files:
  $NAME.tar.gz            graphical + command-line client (GTK 4 >= 4.14 / libadwaita >= 1.5; CLI static)
  $NAME.tar.gz.minisig    detached signature (after --sign)
  aska-drop-$VERSION-linux-x86_64         relay, static-pie (operators)
  aska-drop-$VERSION-linux-x86_64.minisig detached signature (after --sign)
  aska-drop-deploy-$VERSION.tar.gz        installer, torrc, systemd unit and the Relay Operator Guide
  aska-drop-deploy-$VERSION.tar.gz.minisig detached signature (after --sign)
  SHA256SUMS.txt          hashes of the files above (signed as SHA256SUMS.txt.minisig after --sign)
Rekor transparency entry: (filled in by --rekor)

Verify before first use: compare sha256sum of the tarball with the fingerprint you received out
of band (and the signatures with the public key above); unpack; run \`bin/aska verify\` — it must
say MATCH. The User Guide is docs/USER_GUIDE.md inside the tarball; the Relay Operator Guide is
in the deploy tarball. Never install an update because software told you one exists.
TXT
  echo "release.sh: candidate in $OUT — now run: scripts/release.sh $TAG --sign"
  echo "            (the tarball is produced by --sign, after SHA256SUMS inside it is signed)"
  ;;

sign)
  SECKEY="${ASKA_RELEASE_SECKEY:-$HOME/.minisign/aska-release.key}"
  [ -f "$SECKEY" ] || { echo "release.sh: secret key $SECKEY not found (ASKA_RELEASE_SECKEY)" >&2; exit 1; }
  [ -d "$OUT/$NAME" ] || { echo "release.sh: no candidate in $OUT — run the build step first" >&2; exit 1; }
  # 1. Sign the hash list inside the tarball directory, then make the tarball (deterministic).
  minisign -S -s "$SECKEY" -m "$OUT/$NAME/SHA256SUMS" -t "aska $TAG SHA256SUMS" ${ASKA_SIGN_BATCH:+-W}
  export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --pretty=%ct)}"
  case "$SOURCE_DATE_EPOCH" in ''|*[!0-9]*) echo "release.sh: SOURCE_DATE_EPOCH is not a number ('$SOURCE_DATE_EPOCH')" >&2; exit 1;; esac
  ( cd "$OUT" && tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
      -cf - "$NAME" | gzip -n > "$NAME.tar.gz" )
  # 2. Detached signatures over the files a user downloads, and a signed list of them.
  ( cd "$OUT" && sha256sum "$NAME.tar.gz" "aska-drop-$VERSION-linux-x86_64" "aska-drop-deploy-$VERSION.tar.gz" > SHA256SUMS.txt )
  for f in "$OUT/$NAME.tar.gz" "$OUT/aska-drop-$VERSION-linux-x86_64" "$OUT/aska-drop-deploy-$VERSION.tar.gz" "$OUT/SHA256SUMS.txt"; do
    minisign -S -s "$SECKEY" -m "$f" -t "aska $TAG $(basename "$f")" ${ASKA_SIGN_BATCH:+-W}
  done
  minisign -V -p "$PUBFILE" -m "$OUT/$NAME.tar.gz" >/dev/null && echo "release.sh: signatures verify with $PUBFILE"
  # 3. Self-check: the shipped binary must verify itself from inside the unpacked tarball.
  # Read the whole output first: piping into `grep -q` closed the pipe early and the CLI aborted
  # on the next write ("Aborted" in the log; harmless, CLI fix scheduled for 1.0.1).
  VERIFY_OUT="$(cd "$OUT/$NAME" && ./bin/aska --stdin --yes verify 2>/dev/null || true)"
  printf '%s\n' "$VERIFY_OUT" | grep -q "status: MATCH" \
    && echo "release.sh: aska verify → MATCH" || { echo "release.sh: aska verify did NOT report MATCH" >&2; exit 1; }
  cp "$PUBFILE" "$OUT/"
  echo "release.sh: signed release in $OUT"
  ( cd "$OUT" && cat SHA256SUMS.txt )
  ;;

rekor)
  command -v rekor-cli >/dev/null || { echo "release.sh: rekor-cli not installed (https://github.com/sigstore/rekor)" >&2; exit 1; }
  ENTRY="$(rekor-cli upload --artifact "$OUT/$NAME.tar.gz" --signature "$OUT/$NAME.tar.gz.minisig" \
            --public-key "$PUBFILE" --pki-format minisign 2>&1 | tail -1)"
  echo "$ENTRY" | tee "$OUT/REKOR.txt"
  sed -i "s|^Rekor transparency entry: .*|Rekor transparency entry: $ENTRY|" "$OUT/RELEASE-NOTES.txt"
  ;;
*)
  echo "release.sh: unknown mode $MODE" >&2; exit 1;;
esac
