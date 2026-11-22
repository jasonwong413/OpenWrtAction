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
IhShCEUoQhGKUIQiFKEIRbh6+H+4wZqpAIACAA==
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
