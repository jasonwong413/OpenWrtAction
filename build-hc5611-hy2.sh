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
packages=(
    -dnsmasq -ppp -ppp-mod-pppoe -luci -luci-theme-bootstrap -luci-app-package-manager
    dnsmasq-full uhttpd uhttpd-mod-ubus luci-base luci-mod-admin-full luci-app-firewall
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
if grep -E '^xray[^[:space:]]* - ' "$manifest"; then exit 1; fi
"$workspace/ib/staging_dir/host/bin/fwtool" -i metadata.json "$image"
jq -e '.supported_devices == ["hiwifi,hc5611"]' metadata.json
mkdir -p "$output/firmware-hy2-anytls"
cp "$image" "$manifest" metadata.json "$output/firmware-hy2-anytls/"
(
    cd "$output/firmware-hy2-anytls"
    sha256sum "$(basename "$image")" > SHA256SUMS
)
printf 'Image bytes: %s. Partition remainder: %s bytes.\n' "$bytes" "$((15808 * 1024 - bytes))"
