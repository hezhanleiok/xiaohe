# 彼岸 Ther · Android

> 分支说明：本分支 `xiaohe-android` 只放 **Android 客户端**。
> 仓库的 `main` 分支放的是 Windows 客户端（Go + Aether Core），两者没有共同祖先，互不影响。

彼岸 Ther 是一个 Android 端的隐私网络客户端（arm64-v8a，包名 `com.aether.ther`）。
一条隧道里可以换不同的承载方式，出口也可以叠加 Psiphon / Tor。

## 当前版本

| 项 | 值 |
|---|---|
| 版本 | `0.1.31`（versionCode 32） |
| 架构 | arm64-v8a |
| 包体 | 约 36.9 MB（debug 构建，未签名发布） |
| 内置核心 | `engine.aar`（wireguard-go + AWG junk 补丁）· `libaether.so` 2.3.0 · `libpsiphon.so` 2.3.0 |

0.1.31 只改 MASQUE 的连接参数（`core/AetherCore.kt`）：

- **MASQUE H3**：等网关预算 75s → 150s，先 `turbo` 扫描（首个可用网关即建链，实测 7s），
  失败再退回一次完整扫描（120s），两次都空才降级 H2。
- **MASQUE-in-MASQUE**：强制 `AETHER_SCAN=verified`。非 verified 模式会拿外层同 `/24`
  的邻居当内层落点，被边缘以 `CRYPTO_ERROR 0x128` 拒绝（12/12 实测）；改成跨 `/24`
  且验证过的边缘后一次握手成功。成功两跳记在 `files/core/mim-peers.txt`，
  下次直接回放（69s → 10s），失效自动清除重扫。
- **加固**：固定 `AETHER_IP=v4`（双栈会挑到 IPv6 端点，握手成功但数据面不通）；
  补上 `AETHER_MASQUE_STARTUP_SECS`（MIM 150s / H2 180s）。

## 能力

| 能力 | 说明 |
|---|---|
| 三套承载 | 原生 WireGuard / AmneziaWG；Aether 核心的 MASQUE H2、MASQUE H3、GOOL、MASQUE-in-MASQUE；双层伪装 Warp-in-Warp（WG in WG） |
| 出口可选 | 默认 WARP 出口，也可叠加 Psiphon（可选出口地区）或 Tor；出口地区是速度的第一杠杆 |
| DNS 防泄漏 | 隧道内接管解析，支持自定义上游；关闭时可走物理链路 |
| 分流规则 | 全局 / 绕过大陆 / 黑名单，规则页可编辑直连与阻断条目 |
| 排障 | 连接过程逐阶段写日志，可一键导出；失败原因写成人能看懂的一句话 |

## 构建

需要 JDK 17、Android SDK（`ANDROID_HOME`）、NDK 27、Go + `gomobile`。

```bash
# 1) 重建引擎 AAR（Go 侧）
cd engine
export JAVA_TOOL_OPTIONS="-Dfile.encoding=UTF-8"     # 不设会按 GBK 读中文 javadoc，aar 变 0 字节
"$(go env GOPATH)/bin/gomobile.exe" bind -target android/arm64 -androidapi 26 \
    -o ../app/libs/engine.aar .

# 2) 打包 APK
cd ..
rm -rf app/build/outputs/apk app/build/intermediates/apk   # 不清会留孤儿 libgojni.so
./gradlew :app:assembleDebug
```

产物：`app/build/outputs/apk/debug/app-debug.apk`（校验：zip 内只应有 4 个 `.so`）。

## 文档

- [`基线说明.md`](基线说明.md) —— **唯一的权威文档**。改 `engine/` 或连接流程之前先读它的
  「红线」章节；出现「连不上 / 连上不能用」先查「症状速查」。含完整设计依据、
  已证伪的旧结论、赛风速度实测矩阵。

## 已知限制

- MIM 首次连接需要 60–70 秒（核心的验证扫描会把预算走满），之后约 10 秒。
- MASQUE H2 在部分网络会被 TLS 层拦截，属网络策略；优先用 H3。
- 出口 IP 由 Cloudflare 按网络位置分配，无法指定具体地址。
