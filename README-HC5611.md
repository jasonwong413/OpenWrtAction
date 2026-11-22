# 极路由 GO HC5611 精简固件构建

使用 OpenWrt 25.12.6 的官方 ImageBuilder 与 SDK，为 ramips/mt76x8 的 HiWiFi HC5611 构建。脚本交叉编译精简 sing-box 1.14.4 和 Passwall 的若干依赖，并保留无线中继、iPhone USB 网络共享、Argon 3.1.4 及简体中文。

需要 Linux x86_64、Go 1.26.8 和工作流列出的依赖。运行 bash build-hc5611-compact.sh，或在 Actions 中手动运行 Build HC5611 firmware。成功后，hc5611-firmware 产物包含 sysupgrade 镜像、包清单、机型元数据和 SHA-256 校验值。

构建要求镜像在 15,808 KiB 固件分区内留下至少 512 KiB，并检查 HC5611 机型及必需软件包。官方软件源中的依赖包可能随版本维护而更新，后续构建的二进制文件可能不同。

精简核心保留 VLESS / REALITY、VMess、Trojan、Shadowsocks、SOCKS、HTTP 和 AnyTLS 等常用代理协议。QUIC、WireGuard、TUN、Snell、SSH 和额外管理命令已裁剪。
