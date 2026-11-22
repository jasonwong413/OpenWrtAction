#!/usr/bin/env bash
set -euo pipefail
shopt -s nullglob

output=$(cd -- "$(dirname -- "$0")" && pwd)
workspace=$(mktemp -d "${RUNNER_TEMP:-/tmp}/hc5611.XXXXXXXX")
trap 'rm -rf -- "$workspace"' EXIT
release=https://downloads.openwrt.org/releases/25.12.6
target=$release/targets/ramips/mt76x8
feed=$release/packages/mipsel_24kc/packages
passwall=https://github.com/Openwrt-Passwall/openwrt-passwall2/releases/download/26.11.11-1
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
helpers=(chinadns-ng tcping)
for name in "${helpers[@]}"; do
    cp -R "helpers/$name" sdk/package/
    printf 'CONFIG_PACKAGE_%s=m\n' "$name"
done >> sdk/.config
(
    cd sdk
    make defconfig
    make -j"$(nproc)" package/chinadns-ng/compile         package/tcping/compile
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
    cat > test-protocols.py <<'PROTOCOL_TEST'
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import json
import subprocess
import sys
import tempfile
import threading
import time

invocation = sys.argv[1:]
class Endpoint(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(204)
        self.end_headers()

with tempfile.TemporaryDirectory() as temp:
    directory = Path(temp)
    cert = directory / "cert.pem"
    key = directory / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-keyout", str(key), "-out", str(cert)],
                   check=True, capture_output=True)
    endpoint = ThreadingHTTPServer(("127.0.0.1", 0), Endpoint)
    threading.Thread(target=endpoint.serve_forever, daemon=True).start()
    for protocol, obfs in (("anytls", {}), ("hysteria2", {}), ("hysteria2", {"type":"salamander","password":"local-obfs"}),
                           ("hysteria2", {"type":"gecko","password":"local-obfs","min_packet_size":512,"max_packet_size":1200})):
        options = {"obfs":obfs} if obfs else {}
        server_config = {"inbounds": [{"type":protocol,"listen":"127.0.0.1","listen_port":28443,
                           "users":[{"password":"local-test"}],"tls":{"enabled":True,"certificate_path":str(cert),
                           "key_path":str(key)},**options}], "outbounds":[{"type":"direct","tag":"direct"}]}
        client_config = {"inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":28777}],
                         "outbounds":[{"type":protocol,"server":"127.0.0.1","server_port":28443,
                         "password":"local-test","tls":{"enabled":True,"server_name":"localhost",
                         "certificate_path":str(cert)},**options}]}
        processes = []
        logfile = directory / "log"
        try:
            with logfile.open("wb") as target:
                for name, config in (("server",server_config), ("client",client_config)):
                    path = directory / f"{name}.json"
                    path.write_text(json.dumps(config))
                    processes.append(subprocess.Popen(invocation + ["run","-c",str(path)], stdout=target, stderr=target))
                url = f"http://127.0.0.1:{endpoint.server_port}"
                for attempt in range(12):
                    result = subprocess.run(["curl","-sS","--max-time","2","--noproxy","","--proxy",
                                             "socks5h://127.0.0.1:28777","-o","/dev/null","-w","%{http_code}",url],
                                            capture_output=True)
                    if result.stdout == b"204":
                        print(protocol, obfs.get("type","standard"), "HTTP 204", flush=True)
                        break
                    if any(p.poll() is not None for p in processes):
                        break
                    time.sleep(0.25)
                assert result.stdout == b"204", logfile.read_text()
        finally:
            for process in processes:
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=5)
    endpoint.shutdown()
PROTOCOL_TEST
    python3 test-protocols.py qemu-mipsel -cpu 24Kc ./sing-box-core
    qemu-mipsel -cpu 24Kc ./sing-box-core version
    qemu-mipsel -cpu 24Kc ./sing-box-core check -c protocol-check.json
fi
mkdir -p ib/packages payload/core/usr/bin payload/usb/usr/bin payload/ios/usr/bin files/etc/uci-defaults
for name in "${helpers[@]}"; do
    mapfile -t built < <(find sdk/bin -name "$name-*.apk")
    test "${#built[@]}" -eq 1
    cp "${built[0]}" ib/packages/
done
download "$passwall/luci-app-passwall2-26.11.11-r1.apk" passwall2.apk 756d9b6a6a7390ce3b7b357fa1b1bbe3b431317cec0fcd6283202c385c0d6303
download "$passwall/luci-i18n-passwall2-zh-cn-26.11.11.apk" ib/packages/luci-i18n-passwall2-zh-cn-26.11.11.apk a1999dc0ed31b755f7cffe19bf2900b2b6200c0898f1732491cb9a8f6dd2f65b
download "$argon/luci-theme-argon-3.1.4-r1.apk" argon.apk 7c9cfc8ab119d33856294f0959f2c267fd20471d5a2326218f3b316a6bd82ca1
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
mkdir payload/argon
"$apk" extract --allow-untrusted --destination payload/argon argon.apk
find payload/argon/www/luci-static/argon -name bg1.webp -delete
"$apk" mkpkg --info 'name:luci-theme-argon' --info 'version:3.1.4-r2' --info 'arch:all' \
    --info 'license:Apache-2.0' --info 'depends:luci-base' --files payload/argon \
    --output ib/packages/luci-theme-argon-3.1.4-r2.apk
mkdir payload/passwall2
"$apk" extract --allow-untrusted --destination payload/passwall2 passwall2.apk
python3 - <<'PASSWALL_DEFAULTS'
from pathlib import Path
root = Path("payload/passwall2")
path = root / "usr/share/passwall2/0_default_config"
data = path.read_text().split("config nodes ", 1)[0]
data = data.replace("\toption node 'rulenode'\n", "")
data = data.replace("option geosite_update '1'", "option geosite_update '0'")
data = data.replace("option geoip_update '1'", "option geoip_update '0'")
path.write_text(data)
controller = root / "usr/lib/lua/luci/controller/passwall2.lua"
assert controller.is_file()
data = controller.read_text()
for page in ("app_update", "rule"):
    data = "".join(line for line in data.splitlines(keepends=True) if f'appname, "{page}"}}, cbi' not in line)
controller.write_text(data)
node_form = root / "usr/lib/lua/luci/model/cbi/passwall2/client/type/1_sing-box.lua"
data = node_form.read_text()
start = data.index('o:value("socks", "Socks")')
end = data.index('local protocol_val', start)
node_form.write_text(data[:start] + (
    'if singbox_tags:find("with_quic") then\n'
    '    o:value("hysteria2", "Hysteria2")\n'
    'end\n'
    'o:value("anytls", "AnyTLS")\n\n'
) + data[end:])
subscription = root / "usr/share/passwall2/subscribe.lua"
data = subscription.read_text()
signature = "local function processData(szType, content, add_mode, group, sub_cfg)\n"
assert data.count(signature) == 1
subscription.write_text(data.replace(signature, signature +
    '    if szType ~= "hysteria2" and szType ~= "hy2" and szType ~= "anytls" then return nil end\n', 1))
PASSWALL_DEFAULTS
pack luci-app-passwall2 26.11.11-r2 GPL-3.0-or-later 'coreutils coreutils-base64 coreutils-nohup coreutils-timeout curl ip-full libuci-lua lua luci-compat luci-lib-jsonc lyaml resolveip tcping unzip dnsmasq-full chinadns-ng sing-box kmod-nft-tproxy kmod-nft-socket' payload/passwall2
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
Tz+ffj79vP+f/w+UFsUJAIACAA==
UI_FILES

packages=(
    -dnsmasq -ppp -ppp-mod-pppoe -luci -luci-theme-bootstrap -luci-app-package-manager -luci-mod-admin-full -luci-mod-status
    dnsmasq-full uhttpd uhttpd-mod-ubus luci-base luci-mod-network luci-mod-system luci-app-firewall
    luci-i18n-base-zh-cn luci-i18n-firewall-zh-cn luci-theme-argon luci-i18n-argon-config-zh-cn
    luci-app-passwall2 luci-i18n-passwall2-zh-cn sing-box chinadns-ng
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
test "$bytes" -le "$(((15808 - 440) * 1024))"
for name in luci-app-passwall2 sing-box dnsmasq-full kmod-nft-tproxy kmod-mt7603 \
    wpad-basic-mbedtls relayd luci-proto-relay kmod-usb-net-ipheth usbmuxd \
    libimobiledevice-utils kmod-usb-net-rtl8152 kmod-usb-net-asix kmod-usb-net-asix-ax88179 \
    kmod-usb-net-cdc-ether kmod-usb-net-cdc-ncm luci-theme-argon luci-i18n-base-zh-cn \
    luci-i18n-passwall2-zh-cn luci-i18n-argon-config-zh-cn; do
    grep -E "^${name} - " "$manifest"
done
if grep -E '^(xray[^[:space:]]*|luci-app-passwall|geoview|v2ray-geoip|v2ray-geosite|luci-mod-status) - ' "$manifest"; then exit 1; fi
"$workspace/ib/staging_dir/host/bin/fwtool" -i metadata.json "$image"
jq -e '.supported_devices == ["hiwifi,hc5611"]' metadata.json
mkdir -p "$output/firmware-hy2-anytls"
cp "$image" "$manifest" metadata.json "$output/firmware-hy2-anytls/"
(
    cd "$output/firmware-hy2-anytls"
    sha256sum "$(basename "$image")" > SHA256SUMS
)
printf 'Image bytes: %s. Partition remainder: %s bytes.\n' "$bytes" "$((15808 * 1024 - bytes))"
