# 极路由 GO HC5611 云编译

构建目标为 OpenWrt 25.12.6、ramips/mt76x8、HiWiFi HC5611。配置包括 Passwall、精简 sing-box、2.4 GHz 无线中继和 iPhone USB 网络共享。LuCI 默认使用 Argon 3.1.4 与简体中文，随固件安装 Passwall、Argon 和防火墙的中文翻译。

sing-box 只启用 uTLS 这一项可选编译特性，用于需要 uTLS 的节点，例如 VLESS/REALITY。此配置关闭 QUIC、WireGuard、gVisor 和 Clash API 等特性，因此依赖 QUIC 的 Hysteria2、TUIC 或 HTTP/3 配置无法使用。Passwall 通过 nftables 透明代理，软件包清单检查会拦截含 Xray 的构建。

## GitHub Actions

将此压缩包的文件放在有写权限的仓库的默认分支根目录。可以使用 OpenWrtAction 的 Fork，保留其中其他目录。注意将隐藏的 `.github/workflows/hc5611.yml` 一并提交。启用 Actions 后运行 **Build HC5611 firmware**。工作流所需权限仅为读取仓库。构建成功后，`hc5611-firmware` artifact 内包含 `.bin`、包清单、最终配置、机型元数据和 SHA-256 校验值。

同一脚本也能在已安装工作流所列依赖的 Linux 主机上以普通用户运行。

```bash
bash build-hc5611.sh
```

OpenWrt 定义的固件分区上限为 15,808 KiB。发布检查要求镜像再留出至少 512 KiB 的分区余量。此余量按镜像总字节数计算，实际可写空间还取决于 flash 擦除块和文件系统开销。工作流在尺寸、目标机型或包清单检查失败时停止发布。

目前这组文件已经做过脚本和 YAML 语法检查，完整 Linux 构建和真机功能尚待验证。
