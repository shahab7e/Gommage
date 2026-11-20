#!/bin/sh
# Build gommage_<version>_amd64.deb into dist/. Run from the repo root on Debian/Ubuntu:
#   sh packaging/linux/build-deb.sh 1.0.0
# pywebview (pure Python) is vendored into /opt/gommage/lib so installing needs no pip or internet;
# the GTK/WebKit bindings come from the distro through the Depends below.
set -eu
VERSION="${1:?usage: build-deb.sh VERSION}"
ROOT="$(mktemp -d)"
APP="$ROOT/opt/gommage"

mkdir -p "$APP/lib" "$ROOT/usr/bin" "$ROOT/usr/share/applications" "$ROOT/usr/share/icons/hicolor/256x256/apps" \
         "$ROOT/usr/share/doc/gommage" "$ROOT/DEBIAN"
cp gommage.py split_engine.py killswitch.py ui.html "$APP/"
cp -r fonts assets "$APP/"
rm -rf "$APP/assets/logo"            # design sources; the app only uses the wordmark below
mkdir -p "$APP/assets/logo"
cp assets/logo/gommage-wordmark-dark.svg "$APP/assets/logo/"
python3 -m pip install --quiet --no-compile --target "$APP/lib" -r requirements.txt
# pywebview's Windows/macOS backends pull in nothing extra here, but drop their native helpers if any slipped in
find "$APP/lib" -name "*.dll" -delete
find "$APP/lib" -name "__pycache__" -type d -prune -exec rm -rf {} +

cat > "$ROOT/usr/bin/gommage" <<'EOF'
#!/bin/sh
exec /usr/bin/python3 /opt/gommage/gommage.py "$@"
EOF
chmod 755 "$ROOT/usr/bin/gommage"

cat > "$ROOT/usr/share/applications/gommage.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=Gommage
Comment=One-tap Tor client for getting around censorship
Exec=gommage
Icon=gommage
Terminal=false
Categories=Network;Security;
Keywords=tor;vpn;proxy;bridge;censorship;
EOF
cp assets/icon.png "$ROOT/usr/share/icons/hicolor/256x256/apps/gommage.png"
cp LICENSE "$ROOT/usr/share/doc/gommage/copyright"

cat > "$ROOT/DEBIAN/control" <<EOF
Package: gommage
Version: $VERSION
Section: net
Priority: optional
Architecture: amd64
Maintainer: Gommage <190859988+shahab7e@users.noreply.github.com>
Depends: python3 (>= 3.10), python3-gi, gir1.2-gtk-3.0, gir1.2-webkit2-4.1 | gir1.2-webkit2-4.0, policykit-1 | pkexec
Recommends: nftables, iproute2, gir1.2-ayatanaappindicator3-0.1
Homepage: https://github.com/shahab7e/Gommage
Description: One-tap Tor client built for heavy censorship
 Connects to Tor through bridges (your own, public lists, Tor's built-ins),
 ranked by speed and past success. Proxy mode or whole-system VPN mode with
 split tunnelling. Tor and sing-box downloads are SHA-256 verified.
EOF

cat > "$ROOT/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
command -v update-desktop-database >/dev/null && update-desktop-database -q /usr/share/applications || true
command -v gtk-update-icon-cache >/dev/null && gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true
EOF
chmod 755 "$ROOT/DEBIAN/postinst"

cat > "$ROOT/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
case "$1" in
  remove|purge)
    systemctl disable --now gommage-killswitch.service 2>/dev/null || true
    rm -f /etc/systemd/system/gommage-killswitch.service /etc/gommage-killswitch.nft
    systemctl daemon-reload 2>/dev/null || true
    nft delete table inet gommage_ks 2>/dev/null || true
    for tool in iptables ip6tables; do
      command -v "$tool" >/dev/null || continue
      while "$tool" -D OUTPUT -j GOMMAGE_KS 2>/dev/null; do :; done
      "$tool" -F GOMMAGE_KS 2>/dev/null || true
      "$tool" -X GOMMAGE_KS 2>/dev/null || true
    done
    ;;
esac
EOF
chmod 755 "$ROOT/DEBIAN/prerm"

find "$ROOT" -type d -exec chmod 755 {} +
find "$ROOT/opt" -type f -exec chmod 644 {} +
mkdir -p dist
dpkg-deb --root-owner-group --build "$ROOT" "dist/gommage_${VERSION}_amd64.deb"
rm -rf "$ROOT"
echo "built dist/gommage_${VERSION}_amd64.deb"
