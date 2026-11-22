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

cat > files/etc/uci-defaults/99-hc5611-luci <<'THEME'
#!/bin/sh
uci set luci.main.lang='zh_cn'
uci set luci.main.mediaurlbase='/luci-static/go'
uci commit luci
THEME
chmod +x files/etc/uci-defaults/99-hc5611-luci
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
z/P/qlB0SwCAAgA=
UI_FILES

packages=(
    -dnsmasq -ppp -ppp-mod-pppoe -luci -luci-theme-bootstrap -luci-app-package-manager -luci-mod-admin-full -luci-mod-status
    dnsmasq-full uhttpd uhttpd-mod-ubus luci-base luci-mod-network luci-mod-system luci-app-firewall
    luci-i18n-base-zh-cn luci-i18n-firewall-zh-cn
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
    kmod-usb-net-cdc-ether kmod-usb-net-cdc-ncm luci-i18n-base-zh-cn \
    luci-i18n-passwall2-zh-cn; do
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
