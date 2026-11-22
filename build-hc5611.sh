#!/usr/bin/env bash
set -euo pipefail

output_dir=$(cd -- "$(dirname -- "$0")" && pwd)
source_dir=${OPENWRT_BUILD_DIR:-"$HOME/hc5611-openwrt"}
release=v25.12.6
argon=v3.1.4
passwall=b3cf8e768ba11d9172e9db7bdd6af17eaf8580f7
passwall_packages=a880c9046f8bd5d2d4f1fb6b8f2e70968c463322

if [[ $(uname -s) != Linux || $(id -u) == 0 ]]; then
    echo "Run as an unprivileged user on Linux." >&2
    exit 1
fi

jobs=${JOBS:-$(nproc)}

fetch() {
    local repo=$1 ref=$2 dir=$3
    if [[ ! -d "$dir/.git" ]]; then
        git init -q "$dir"
    fi
    if ! git -C "$dir" rev-parse --verify HEAD >/dev/null 2>&1; then
        git -C "$dir" fetch --depth=1 "$repo" "$ref"
        git -C "$dir" checkout -q --detach FETCH_HEAD
    fi
    local expected=$ref
    if [[ $ref == v* ]]; then
        expected=$(git ls-remote "$repo" "refs/tags/$ref^{}" | cut -f1)
        if [[ -z $expected ]]; then
            expected=$(git ls-remote "$repo" "refs/tags/$ref" | cut -f1)
        fi
    fi
    test "$(git -C "$dir" rev-parse HEAD)" = "$expected"
}

fetch https://github.com/openwrt/openwrt.git "$release" "$source_dir"
cd "$source_dir"
# Only the packages and LuCI feeds are needed. Keep the commits from the release.
awk '$2 == "packages" || $2 == "luci"' feeds.conf.default |
    sed -E 's@https://git.openwrt.org/(feed|project)/@https://github.com/openwrt/@' > feeds.conf
./scripts/feeds update -a
./scripts/feeds install -a

fetch https://github.com/Openwrt-Passwall/openwrt-passwall.git "$passwall" package/passwall
fetch https://github.com/Openwrt-Passwall/openwrt-passwall-packages.git "$passwall_packages" package/passwall-packages
fetch https://github.com/jerrykuku/luci-theme-argon.git "$argon" package/luci-theme-argon
# Use one definition for each Passwall dependency.
for recipe in package/passwall-packages/*/Makefile; do
    name=$(basename "$(dirname "$recipe")")
    find package/feeds -type l -name "$name" -delete
done

install -D -m 0755 "$output_dir/99-hc5611-luci" files/etc/uci-defaults/99-hc5611-luci
cp "$output_dir/hc5611.config" .config
make defconfig
required=(TARGET_ramips_mt76x8_DEVICE_hiwifi_hc5611 PACKAGE_luci-app-passwall
    PACKAGE_luci-app-passwall_Nftables_Transparent_Proxy PACKAGE_sing-box
    PACKAGE_dnsmasq-full PACKAGE_kmod-mt7603 PACKAGE_wpad-basic-mbedtls
    PACKAGE_relayd PACKAGE_luci-proto-relay PACKAGE_kmod-usb-net-ipheth
    PACKAGE_usbmuxd PACKAGE_libimobiledevice-utils SING_BOX_BUILD_UTLS
    PACKAGE_luci-theme-argon PACKAGE_luci-i18n-argon-config-zh-cn
    PACKAGE_luci-i18n-base-zh-cn PACKAGE_luci-i18n-passwall-zh-cn)
for symbol in "${required[@]}"; do
    grep -Fx "CONFIG_$symbol=y" .config
done
if grep -Eq '^CONFIG_PACKAGE_(xray[^=]*|hysteria|naiveproxy|v2ray-geoip|v2ray-geosite|shadowsocks[^=]*)=[ym]$' .config; then
    echo "Unexpected proxy dependency" >&2
    exit 1
fi

make -j"$jobs" download
make -j"$jobs" V=s

target=bin/targets/ramips/mt76x8
mapfile -t images < <(find "$target" -maxdepth 1 -name '*hiwifi_hc5611-squashfs-sysupgrade.bin')
test "${#images[@]}" -eq 1
image=${images[0]}
bytes=$(stat -c %s "$image")
# Leave at least 512 KiB of the firmware partition available for the overlay.
max_bytes=$(((15808 - 512) * 1024))
if ((bytes > max_bytes)); then
    printf 'Image is %s bytes, exceeding the %s-byte build limit.\n' "$bytes" "$max_bytes" >&2
    exit 1
fi
mapfile -t manifests < <(find "$target" -maxdepth 1 -name '*hiwifi_hc5611*.manifest')
if [[ ${#manifests[@]} -eq 0 ]]; then
    mapfile -t manifests < <(find "$target" -maxdepth 1 -name "*.manifest")
fi
test "${#manifests[@]}" -eq 1
manifest=${manifests[0]}
for package in luci-app-passwall sing-box relayd luci-proto-relay kmod-usb-net-ipheth usbmuxd libimobiledevice-utils luci-theme-argon luci-i18n-base-zh-cn luci-i18n-passwall-zh-cn luci-i18n-argon-config-zh-cn; do
    grep -E "^${package}[[:space:]]" "$manifest"
done
! grep -Eq '^xray[^[:space:]]*[[:space:]]' "$manifest" || exit 1
fwtool=$(find staging_dir -path '*/bin/fwtool' -type f -print -quit)
metadata=$(mktemp)
trap 'rm -f "$metadata"' EXIT
"$fwtool" -i "$metadata" "$image"
jq -e '.supported_devices | index("hiwifi,hc5611") != null' "$metadata"

mkdir -p "$output_dir/firmware"
cp "$image" "$manifest" "$output_dir/firmware/"
cp "$metadata" "$output_dir/firmware/metadata.json"
./scripts/diffconfig.sh > "$output_dir/firmware/build.config"
(
    cd "$output_dir/firmware"
    sha256sum "$(basename "$image")" > SHA256SUMS
)
printf 'Image: %s bytes, partition remainder: %s bytes\n' "$bytes" "$((15808 * 1024 - bytes))"
