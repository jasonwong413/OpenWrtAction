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
