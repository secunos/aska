#!/bin/sh
# Install Aska for the current user (no root): binaries to ~/.local/bin, the desktop entry and
# icons to ~/.local/share. Nothing else is written anywhere. Remove with: rm ~/.local/bin/aska
# ~/.local/bin/aska-gui ~/.local/share/applications/org.aska.Aska.desktop
# ~/.local/share/aska/SHA256SUMS* and
# find ~/.local/share/icons/hicolor -name 'org.aska.Aska*' -delete
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="${XDG_BIN_HOME:-$HOME/.local/bin}"
DATA="${XDG_DATA_HOME:-$HOME/.local/share}"
mkdir -p "$BIN" "$DATA/applications" "$DATA/icons/hicolor"
install -m 0755 "$HERE/bin/aska" "$HERE/bin/aska-gui" "$BIN/"
# The desktop entry gets the absolute path: ~/.local/bin is not on the session PATH until the
# next login on most desktops, and the Activities icon must work right after installing.
sed "s|^Exec=.*|Exec=$BIN/aska-gui|" "$HERE/share/applications/org.aska.Aska.desktop" > "$DATA/applications/org.aska.Aska.desktop"
chmod 0644 "$DATA/applications/org.aska.Aska.desktop"
# The icon theme: every size the brand kit provides, under the app id org.aska.Aska.
for f in "$HERE"/share/icons/hicolor/*/apps/org.aska.Aska*; do
  d="$DATA/icons/hicolor/$(basename "$(dirname "$(dirname "$f")")")/apps"
  mkdir -p "$d" && install -m 0644 "$f" "$d/"
done
command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -f -t "$DATA/icons/hicolor" >/dev/null 2>&1 || true
# A signed release: keep the signed hash list where `aska verify` looks for it after the
# tarball directory is gone (Client Design §9.4).
if [ -f "$HERE/SHA256SUMS.minisig" ]; then
  mkdir -p "$DATA/aska"
  install -m 0644 "$HERE/SHA256SUMS" "$HERE/SHA256SUMS.minisig" "$DATA/aska/"
fi
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$DATA/applications" || true
echo "Installed: $BIN/aska, $BIN/aska-gui and the Aska desktop entry (update-desktop-database also refreshes $DATA/applications/mimeinfo.cache)."
echo "Verify before first use (Client Design §9.4): compare 'sha256sum $BIN/aska-gui' with the release fingerprint you got out of band."
case ":$PATH:" in *":$BIN:"*) ;; *) echo "Note: $BIN is not on your PATH; start with $BIN/aska-gui." ;; esac
