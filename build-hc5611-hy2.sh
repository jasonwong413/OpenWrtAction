#!/usr/bin/env bash
set -euo pipefail
shopt -s nullglob

output=$(cd -- "$(dirname -- "$0")" && pwd)
workspace=$(mktemp -d "${RUNNER_TEMP:-/tmp}/hc5611.XXXXXXXX")
trap 'rm -rf -- "$workspace"' EXIT
release=https://downloads.openwrt.org/releases/25.12.6
target=$release/targets/ramips/mt76x8
feed=$release/packages/mipsel_24kc/packages
passwall=https://github.com/Openwrt-Passwall/openwrt-passwall/releases/download/26.11.11-1
argon=https://github.com/jerrykuku/luci-theme-argon/releases/download/v3.1.4

download() {
    local url=$1 file=$2 digest=$3
    curl --fail --location --silent --show-error --retry 3 "$url" -o "$file"
    printf '%s  %s\n' "$digest" "$file" | sha256sum -c -
}

cd "$workspace"
sdk_archive=openwrt-sdk-25.12.6-ramips-mt76x8_gcc-14.3.0_musl.Linux-x86_64.tar.zst
ib_archive=openwrt-imagebuilder-25.12.6-ramips-mt76x8.Linux-x86_64.tar.zst
download "$target/$sdk_archive" "$sdk_archive" 739cc7cdf28661e3e3a9c65a36ef40de2e66e2900e593c71888074ef6bf40eef
download "$target/$ib_archive" "$ib_archive" 7f26c50440cadd83362c444778f80f4a214ee76f3c192ef85ef074f2c56d89ec
mkdir sdk ib sing-box
tar --zstd -xf "$sdk_archive" --strip-components=1 -C sdk
tar --zstd -xf "$ib_archive" --strip-components=1 -C ib

git init -q helpers
git -C helpers fetch --depth 1 https://github.com/Openwrt-Passwall/openwrt-passwall-packages.git     a880c9046f8bd5d2d4f1fb6b8f2e70968c463322
git -C helpers checkout -q --detach FETCH_HEAD
helpers=(chinadns-ng dns2socks tcping ipt2socks)
for name in "${helpers[@]}"; do
    cp -R "helpers/$name" sdk/package/
    printf 'CONFIG_PACKAGE_%s=m\n' "$name"
done >> sdk/.config
(
    cd sdk
    make defconfig
    make -j"$(nproc)" package/chinadns-ng/compile package/dns2socks/compile         package/tcping/compile package/ipt2socks/compile
)

download https://codeload.github.com/SagerNet/sing-box/tar.gz/v1.14.4 sing-box.tar.gz     0958ccd23b1ea9a141d715d15478b1e040fd04bcca19d8ff5529636b1b753e18
tar -xzf sing-box.tar.gz --strip-components=1 -C sing-box
(
    cd sing-box
    python3 - <<'PY'
from pathlib import Path

commands = Path("cmd/sing-box")
for pattern in ("cmd_api*.go", "cmd_tools*.go", "cmd_geoip*.go", "cmd_geosite*.go", "cmd_schema.go"):
    for path in commands.glob(pattern):
        path.unlink()

registry = Path("include/registry.go")
removed = {"tun", "tor", "bridge", "ssh", "snell", "naive", "mdns", "api", "resolved", "ssmapi", "originca", "vless", "vmess", "trojan", "shadowsocks", "shadowtls"}
imports = removed | {"origin_ca"}
lines = [
    line for line in registry.read_text().splitlines()
    if not any(line.endswith("/" + name + '"') for name in imports)
    and not any(line.strip().startswith(name + ".Register") for name in removed)
]
registry.write_text("\n".join(lines) + "\n")

quic = Path("include/quic.go")
quic.write_text("\n".join(
    line for line in quic.read_text().splitlines()
    if not any(part in line for part in (
        '/protocol/hysteria"', '/protocol/tuic"', '/protocol/naive/quic"',
        '/transport/v2rayquic"', 'hysteria.Register', 'tuic.Register',
    ))
) + "\n")
PY
    CGO_ENABLED=0 GOOS=linux GOARCH=mipsle GOMIPS=softfloat go build         -tags with_quic,with_utls -gcflags=all=-l -trimpath         -ldflags '-s -w -buildid= -X github.com/sagernet/sing-box/constant.Version=1.14.4'         -o "$workspace/sing-box-core" ./cmd/sing-box
)
cat > protocol-check.json <<'JSON'
{
  "inbounds": [
    {"type":"tproxy","tag":"tp","listen":"127.0.0.1","listen_port":1041},
    {"type":"socks","tag":"local","listen":"127.0.0.1","listen_port":1070}
  ],
  "outbounds": [
    {"type":"hysteria2","tag":"hy2","server":"192.0.2.2","server_port":443,"password":"example","tls":{"enabled":true,"server_name":"example.com"}},
    {"type":"anytls","tag":"any","server":"192.0.2.3","server_port":443,"password":"example","tls":{"enabled":true,"server_name":"example.com"}},
    {"type":"direct","tag":"direct"}
  ],
  "route":{"final":"hy2"}
}
JSON
if command -v qemu-mipsel >/dev/null; then
    qemu-mipsel -cpu 24Kc ./sing-box-core version
    qemu-mipsel -cpu 24Kc ./sing-box-core check -c protocol-check.json
fi
mkdir -p ib/packages payload/core/usr/bin payload/usb/usr/bin payload/ios/usr/bin files/etc/uci-defaults
for name in "${helpers[@]}"; do
    mapfile -t built < <(find sdk/bin -name "$name-*.apk")
    test "${#built[@]}" -eq 1
    cp "${built[0]}" ib/packages/
done
download "$passwall/25.12%2B_luci-app-passwall-26.11.11-r1.apk"     ib/packages/luci-app-passwall-26.11.11-r1.apk f428e5f64eda93f7c134fa0b92e7d2a706030ad2b3cee98e3cb87e790771c870
download "$passwall/25.12%2B_luci-i18n-passwall-zh-cn-26.11.11.apk"     ib/packages/luci-i18n-passwall-zh-cn-26.11.11.apk 838c60bf9afe469cdf0fec0ddc3c8e5b8b77a4e56f8dd866813e8bd0c37fb725
download "$argon/luci-theme-argon-3.1.4-r1.apk"     ib/packages/luci-theme-argon-3.1.4-r1.apk 7c9cfc8ab119d33856294f0959f2c267fd20471d5a2326218f3b316a6bd82ca1
download "$argon/luci-i18n-argon-config-zh-cn-3.1.4-r1.apk"     ib/packages/luci-i18n-argon-config-zh-cn-3.1.4-r1.apk 84cfcc87e2ce7d5b157d64fa496139a3386fba6b6ee0eca88ff2f0e9283e7657
download "$feed/usbutils-019-r1.apk" usbutils.apk     a2549ec2636d056a3862a7b1c2e7e057040538a5effd06d700c9b95f77266f8d
download "$feed/libimobiledevice-utils-2025.07.29~c269d7e3-r2.apk" idevice.apk     67597ee9eb4706c4674bdda0abbb08f7d20a0452959d55810dce9dfd0229335f
apk="$workspace/ib/staging_dir/host/bin/apk"
mkdir stock-usb stock-ios
"$apk" extract --allow-untrusted --destination stock-usb usbutils.apk
"$apk" extract --allow-untrusted --destination stock-ios idevice.apk
install -m 755 sing-box-core payload/core/usr/bin/sing-box
install -m 755 stock-usb/usr/bin/usbreset payload/usb/usr/bin/
install -m 755 stock-ios/usr/bin/idevicepair stock-ios/usr/bin/idevice_id payload/ios/usr/bin/

pack() {
    local name=$1 version=$2 license=$3 dependencies=$4 directory=$5
    "$apk" mkpkg --info "name:$name" --info "version:$version" --info 'arch:mipsel_24kc' \
        --info "license:$license" --info "depends:$dependencies" \
        --files "$directory" --output "ib/packages/$name-$version.apk"
}
pack sing-box 1.14.4-r1 GPL-3.0-or-later 'ca-bundle kmod-inet-diag kmod-netlink-diag' payload/core
pack usbutils 019-r2 GPL-2.0-only libc payload/usb
pack libimobiledevice-utils 2025.07.29~c269d7e3-r3 GPL-2.0-or-later libimobiledevice payload/ios

install -m 755 "$output/99-hc5611-luci" files/etc/uci-defaults/99-hc5611-luci
mkdir -p files/etc/hotplug.d/net
cat > files/etc/uci-defaults/95-hc5611-iphone <<'SH'
#!/bin/sh
set -e

. /lib/functions.sh
if ! uci -q get network.iphone >/dev/null; then
    uci set network.iphone=interface
    uci set network.iphone.proto=dhcp
    uci set network.iphone.device=iphoneusb
    uci set network.iphone.metric=20
    uci commit network
fi

attach_iphone() {
    local section="$1" name networks
    config_get name "$section" name
    [ "$name" = wan ] || return 0
    config_get networks "$section" network
    case " $networks " in
        *" iphone "*) ;;
        *) uci add_list "firewall.$section.network=iphone";;
    esac
}
config_load firewall
config_foreach attach_iphone zone
uci commit firewall
SH
chmod 755 files/etc/uci-defaults/95-hc5611-iphone
cat > files/etc/hotplug.d/net/20-hc5611-iphone <<'SH'
#!/bin/sh

[ "$ACTION" = add ] || return 0
[ -n "$INTERFACE" ] && [ "$INTERFACE" != iphoneusb ] || return 0
driver=$(readlink "/sys/class/net/$INTERFACE/device/driver") || return 0
[ "${driver##*/}" = ipheth ] || return 0

if ip link set dev "$INTERFACE" name iphoneusb; then
    logger -t iphone-usb "Registered iPhone USB Ethernet as iphoneusb"
else
    logger -t iphone-usb "Could not rename $INTERFACE to iphoneusb"
fi
SH
chmod 755 files/etc/hotplug.d/net/20-hc5611-iphone
sed -i 's/^CONFIG_TARGET_SQUASHFS_BLOCK_SIZE=.*/CONFIG_TARGET_SQUASHFS_BLOCK_SIZE=1024/' ib/.config
# Add the HC5611 management interface to the ImageBuilder file overlay.
base64 -d <<'UI_FILES' | tar -xz -C files
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
zwP5/H8i/nUlAPAAAA==
UI_FILES

packages=(
    -dnsmasq -ppp -ppp-mod-pppoe -luci -luci-theme-bootstrap -luci-app-package-manager -luci-mod-admin-full -luci-mod-status
    dnsmasq-full uhttpd uhttpd-mod-ubus luci-base luci-mod-network luci-mod-system luci-app-firewall
    luci-i18n-base-zh-cn luci-i18n-firewall-zh-cn luci-theme-argon luci-i18n-argon-config-zh-cn
    luci-app-passwall luci-i18n-passwall-zh-cn sing-box ipt2socks
    kmod-nft-socket kmod-nft-tproxy relayd luci-proto-relay kmod-usb-net-ipheth usbmuxd
    libimobiledevice-utils kmod-usb-net-rtl8152 kmod-usb-net-asix
    kmod-usb-net-asix-ax88179 kmod-usb-net-cdc-ether kmod-usb-net-cdc-ncm
)
make -C ib image PROFILE=hiwifi_hc5611 PACKAGES="${packages[*]}" FILES="$workspace/files"

directory=ib/bin/targets/ramips/mt76x8
images=("$directory"/*hiwifi_hc5611-squashfs-sysupgrade.bin)
manifests=("$directory"/*hiwifi_hc5611.manifest)
test "${#images[@]}" -eq 1
test "${#manifests[@]}" -eq 1
image=${images[0]}
manifest=${manifests[0]}
bytes=$(stat -c %s "$image")
test "$bytes" -le "$(((15808 - 512) * 1024))"
for name in luci-app-passwall sing-box dnsmasq-full kmod-nft-tproxy kmod-mt7603 \
    wpad-basic-mbedtls relayd luci-proto-relay kmod-usb-net-ipheth usbmuxd \
    libimobiledevice-utils kmod-usb-net-rtl8152 kmod-usb-net-asix kmod-usb-net-asix-ax88179 \
    kmod-usb-net-cdc-ether kmod-usb-net-cdc-ncm luci-theme-argon luci-i18n-base-zh-cn \
    luci-i18n-passwall-zh-cn luci-i18n-argon-config-zh-cn; do
    grep -E "^${name} - " "$manifest"
done
if grep -E '^(xray[^[:space:]]*|luci-mod-status) - ' "$manifest"; then exit 1; fi
"$workspace/ib/staging_dir/host/bin/fwtool" -i metadata.json "$image"
jq -e '.supported_devices == ["hiwifi,hc5611"]' metadata.json
mkdir -p "$output/firmware-hy2-anytls"
cp "$image" "$manifest" metadata.json "$output/firmware-hy2-anytls/"
(
    cd "$output/firmware-hy2-anytls"
    sha256sum "$(basename "$image")" > SHA256SUMS
)
printf 'Image bytes: %s. Partition remainder: %s bytes.\n' "$bytes" "$((15808 * 1024 - bytes))"
