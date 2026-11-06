<p align="center">
  <strong>eCapture Decryptor</strong><br />
  使用 SSLKEYLOG 密钥或 pcapng 内嵌的 TLS Decryption Secrets Block（DSB）解密 pcapng 中 TLS/QUIC 流量的 Go 语言库。
</p>

<p align="center">
  <a href="./README.md">English</a> · <strong>汉字</strong><br />
  <a href="https://github.com/gojue/ecapture_decryptor/releases"><img alt="最新版本" src="https://img.shields.io/github/v/release/gojue/ecapture_decryptor?display_name=tag&include_prereleases&sort=semver" /></a>
  <a href="https://pkg.go.dev/github.com/gojue/ecapture_decryptor"><img alt="Go 参考文档" src="https://pkg.go.dev/badge/github.com/gojue/ecapture_decryptor.svg" /></a>
</p>

> [!NOTE]
> 仓库名为 `ecapture_decryptor`，Go 模块路径为 `github.com/gojue/ecapture_decryptor`；根包、C 库文件和发布压缩包均沿用 `ecapture_decryptor` 名称。

----

<!-- MarkdownTOC autolink="true" -->
- [简介](#简介)
- [特性](#特性)
- [快速开始](#快速开始)
  - [安装](#安装)
  - [解密 pcapng 文件](#解密-pcapng-文件)
  - [增量 pcapng + DSB](#增量-pcapng--dsb)
  - [基本使用](#基本使用)
- [使用方式](#使用方式)
- [构建](#构建)
- [架构](#架构)
- [文档](#文档)
- [许可证](#许可证)
- [贡献](#贡献)
- [致谢](#致谢)
<!-- /MarkdownTOC -->

# 简介

eCapture Decryptor 解密 pcapng 文件中捕获的 TLS 与 QUIC 流量。TLS 密钥可来自独立的 SSLKEYLOG 文件、pcapng 内嵌的 TLS Decryption Secrets Block（DSB），或同时使用两种来源。

SDK 只负责解密与协议解析，不强制输出格式。结果以 `DecryptedPacket` 结构输出，由调用方自由处理（JSON、HAR、流式输出等）。

# 特性

- 🔓 **解密 TLS/QUIC 流量**：支持外部 SSLKEYLOG 文件和 pcapng 内嵌 DSB
- 🌐 **多协议支持**：HTTP/1.0、HTTP/1.1、HTTP/2、HTTP/3、WebSocket
- **显式 DNS、MQTT 与 Redis 解析**：Go API 可选择 DoT、DoH、DoQ、MQTT 3.1.1 或定长 Redis RESP2/RESP3。
- 📦 **灵活输出**：输出 `DecryptedPacket` 结构，由调用方自由处理
- **原始流与诊断**：通过 `DecryptPcapngStreamWithOptions` / `WithOptions` 显式选择已认证的 TLS 字节或 QUIC STREAM chunk，详见 [API 契约](docs/API.md#decryptpcapngstreamwithoptions--withoptions)。
- 🔧 **多种使用方式**：Go 库、静态链接库（`.a`）、命令行工具
- 🎯 **职责清晰**：只负责解密和协议解析，不强制输出格式

Go 调用方可以用 `types.DecryptOptions{HTTPEvents: true}` 接收 HTTP/1、2、3 的 headers、正文片段、SSE、trailers 与 end/reset/partial 事件。正文按消息和方向独立维护 offset。增量 HTTP 和 raw QUIC 可以累计交付超过 16 MiB，乱序缓存仍受限。gzip 展开需显式设置每条消息的展开额度。[增量事件契约](docs/API.md#http-增量事件)

HTTP/1 WebSocket 支持跨 record 的握手校验、双向分片、ping/pong/close 和协商后的 permessage-deflate（含 context takeover），消息与压缩缓存有界。`HTTPEvents` 模式为 HTTP/2 gRPC 增加流结束前的完整 `grpc_message` 输出，含分方向消息边界、gzip 消息压缩和状态 trailers；无 descriptor 时保留原始 Protobuf 字节。详见 [WebSocket 与 gRPC 契约](docs/API.md#websocket)。

Go 文件或流式 API 可用 `types.DecryptOptions{ApplicationProtocol: "doh"}` 显式选择 `dot`、`doh`、`doq`、`mqtt`、`redis`，空值保留原有 HTTP/WebSocket 识别。选择作用于本次调用的所有连接，与 raw/HTTP 增量输出及 gzip 展开互斥。DNS 支持 TLS、HTTP/1.x–3、QUIC 上的普通查询；DoQ 必须显式选择，仅支持 1-RTT，在握手 secrets 足以观察协商 ALPN 时核对它。MQTT 支持 3.1.1 控制包，不跟踪 ACK 投递结果；Redis 支持定长 RESP2/RESP3、流水线响应及 Pub/Sub。输出保留 DNS wire 或完整 MQTT/RESP 字节及协议元数据。[字段、上限与未支持模式](docs/API.md#applicationprotocol)见 API 文档；CLI/C 示例尚未提供该选项。

Go API 可通过 `TLSUpgrade` 显式选择 SMTP、IMAP、POP3、LDAP、PostgreSQL、MySQL 或 HTTP/1 CONNECT 协商，并用 `https-connect` 解密一层内层 TLS。升级被拒绝后保持明文，不扫描 TLS 前缀；升级后的载荷沿用已有应用/raw 输出，缺内层密钥仍保留可解的外层字节。[协商范围、层级与上限](docs/API.md#tlsupgrade)见 API 文档。

### QUIC / HTTP/3 输入要求

解密 HTTP/3 需要包含客户端 Initial（其中有 ClientHello）的双向 UDP 抓包，以及匹配该连接的 TLS 1.3 SSLKEYLOG。密钥可作为外部文件传入，也可放在 pcapng 的 DSB 中。解析器按 QUIC 连接、包号和 STREAM 偏移重组数据，再按 HTTP/3 请求流输出 `http/3` 的 `DecryptedPacket`。

仓库中的 [Linux HTTP/3 抓包](test/fixtures/http3_capture/README.md)与 [Linux HTTP/1.x 和 HTTP/2 抓包](test/fixtures/http_tcp_capture/README.md)由 `tcpdump` 和 eCapture 实际捕获，覆盖外部密钥、内嵌 DSB 和 DSB 文件的流式读取。新增独立回环抓包覆盖 QUIC v1/v2、AES-128-GCM 的双向多次 Key Update。SDK 从初始 application traffic secret 派生后续密钥，并保留上一代处理乱序；[边界与失败行为](docs/API.md#quic-key-update)见 API 文档。AES-256-GCM、ChaCha20-Poly1305 的更新有向量和状态测试，尚无真实抓包覆盖；draft-29 仍未通过真实抓包验证。另有 aioquic 1.3.0 独立抓包，实测 v1/v2 × 三种套件的握手与应用解密、CID 轮换/NAT rebinding、Retry、版本协商和 accepted/rejected 0-RTT；它不扩大上述 Key Update 的真实套件覆盖范围。[连接身份与 early data 契约](docs/API.md#quic-连接身份retryvn-与-0-rtt)见 API 文档。HTTP/3 支持连接级动态 QPACK、控制流、信息响应、独立 trailers、push 响应与 RESET_STREAM 取消。独立 QUIC v1 抓包验证了双向动态 QPACK、迟到 encoder 指令及这些消息状态；[输出契约与上限](docs/API.md#http3)见 API 文档。

# 快速开始

## 安装

```bash
go get github.com/gojue/ecapture_decryptor
```

## 解密 pcapng 文件

`DecryptPcapFile` 的 `keylogReader` 可以为 `nil`，此时从 pcapng 的 DSB 读取密钥；传入 SSLKEYLOG 文件读取器时，也会读取 pcapng 中的 DSB。两个来源可以同时使用。

```go
// 仅使用 pcapng 内嵌的 DSB。
err := ecapture_decryptor.DecryptPcapFile(nil, pcapngFile, packetChan)

// 使用外部 SSLKEYLOG 文件；pcapng 内若有 DSB 也会一并加载。
err = ecapture_decryptor.DecryptPcapFile(keylogFile, pcapngFile, packetChan)
```

## 增量 pcapng + DSB

`DecryptPcapngStream(ctx, input, emit)` 从持续增长的 pcapng `io.ReadCloser` 读取完整块，并在 DSB 到达时立即加载 NSS Key Log 密钥。DSB 可以晚于握手、应用数据，甚至最后一个网络包。SDK 按 TCP 序号重组、去重，并输出完整的 HTTP/1.1 或 HTTP/2 请求/响应；`emit` 返回错误会停止读取并返回该错误。取消 `ctx` 会关闭 `input`，以解除阻塞读取。调用方应按需给 `input` 配置能够被 `Close` 中断的实现，例如 `io.PipeReader` 或网络连接。

QUIC 在匹配的密钥到达时也会重试缓存包。因此，即使 DSB 晚于最后一个 UDP 包，
输入保持打开时仍可输出 HTTP/3 消息或原始 STREAM chunk。原有待解密包上限和
关闭时缺少密钥的错误语义保持不变。

```go
err := ecapture_decryptor.DecryptPcapngStream(ctx, input, func(message *types.DecryptedPacket) error {
    // message.Data 是完整 HTTP 消息；Metadata 包含 host / authority 和 stream_id。
    return handle(message)
})
```

eCapture 集成及其源码和二进制分发（含商业使用）适用 [LICENSE](LICENSE) 中的 **eCapture Integration Exception**。其他 SDK 用途仍按原有授权条款处理。

## 基本使用

```go
package main

import (
    "log"
    "os"

    "github.com/gojue/ecapture_decryptor"
    "github.com/gojue/ecapture_decryptor/types"
)

func main() {
    keylog, _ := os.Open("sslkey.log")
    pcap, _ := os.Open("traffic.pcap")
    defer keylog.Close()
    defer pcap.Close()

    // 创建 channel 接收解密的包
    packetChan := make(chan *types.DecryptedPacket, 100)

    // 处理解密的包
    go func() {
        for packet := range packetChan {
            log.Printf("[%s] %s: %d bytes",
                packet.Protocol,   // "http/1.1"、"http/2" 等
                packet.Direction,  // "request" 或 "response"
                len(packet.Data))  // 解密后的数据
        }
    }()

    // 解密
    err := ecapture_decryptor.DecryptPcapFile(keylog, pcap, packetChan)
    if err != nil {
        log.Fatal(err)
    }

    close(packetChan)
}
```

# 使用方式

公开 API 位于根包：

- `DecryptPcapFile(keylogReader, pcapFileHandle, packetChan)` — 解密 pcap/pcapng 文件
- `DecryptLiveTraffic(keylogReader, pcapHandle, packetChan)` — 解密实时/流式 pcap 数据源
- `DecryptPcapngStream(ctx, input, emit)` — 流式解密持续增长的 pcapng（含延迟 DSB）
- `DecryptWithConfig(config)` / `NewDecryptorConfig()` — 基于 Builder 模式的高级配置

[命令行示例](examples/go_demo/README.md)（`bin/ecapture_decryptor`）演示了离线解密与 JSON/HAR 导出：

```bash
./bin/ecapture_decryptor -pcap traffic.pcapng -sslkeylog sslkey.log -v
./bin/ecapture_decryptor -pcap traffic-with-dsb.pcapng -json output.json
./bin/ecapture_decryptor -pcap traffic.pcapng -sslkeylog sslkey.log -har output.har
```

完整的 API 参考、`DecryptedPacket` 模型、协议元数据以及 C/C++ 用法，请参阅：

- **[API 参考](docs/API.md)** — 完整的 Go API、数据类型和元数据格式
- **[C/C++ 示例](examples/c_demo/README.md)** — 静态库用法、C API 函数和编译参数

# 构建

```bash
make build-static                  # 静态链接库 (.a)
make build-shared                  # 动态链接库 (.dylib / .so)
make -C examples/go_demo build     # Go 命令行示例
make -C examples/c_demo all        # C 示例程序
make test                          # 运行测试
make clean                         # 清理构建产物
```

构建产物包括 `bin/ecapture_decryptor`（命令行工具）、`lib/libecapture_decryptor.a`（静态库）、`lib/libecapture_decryptor.dylib`/`.so`（动态库）、`include/libecapture_decryptor.h`（C 头文件）以及 C 示例程序。默认构建已应用 `-s -w` 与 `-trimpath` 以减小二进制体积。

详见 **[Makefile 指南](docs/MAKEFILE_GUIDE.md)** 与 **[开发指南](docs/DEVELOPMENT.md)**。

# 架构

SDK 采用分层结构：公开 API（`api.go` / `factory.go`）→ 协议解析（`protocol/`）→ 传输层解密（`transport/`，TLS/QUIC）→ 密码学（`crypto/`，密钥管理）→ 数据包捕获（`gopacket`）。核心 SDK 输出 `DecryptedPacket`，HAR 与 JSON 输出由调用方或示例程序生成。

详见 **[架构文档](docs/ARCHITECTURE.md)**，了解分层设计、模块职责、数据流与设计原则。

# 文档

- **[文档索引](docs/README.md)** — 面向用户、开发者和维护者的导航
- **[CHANGELOG.md](CHANGELOG.md)** — 版本变更历史
- **[API 参考](docs/API.md)** · **[架构文档](docs/ARCHITECTURE.md)** · **[开发指南](docs/DEVELOPMENT.md)** · **[Makefile 指南](docs/MAKEFILE_GUIDE.md)**
- **[发布指南](docs/RELEASE_GUIDE.md)** · **[发布快速参考](docs/RELEASE_QUICKREF.md)** · **[发布示例](docs/RELEASE_EXAMPLES.md)**

# 许可证

### ⚠️ 双重许可模式

本项目采用**双重许可模式**：

#### 1. 源代码许可

**版权所有 © 2024-2026 CFC4N (cfc4n.cs@gmail.com)。保留所有权利。**

源代码为**专有软件**，未经明确书面许可，**禁止任何形式的使用、复制、修改或分发**。查看源代码不授予任何使用权限。

#### 2. 二进制库许可

**版权所有 © 2024-2026 CFC4N (cfc4n.cs@gmail.com)。保留所有权利。**

编译后的二进制库（`.a`、`.so`、`.dylib`）仅可用于**非商业用途**：个人使用、研究和教育、评估和测试，以及与非商业应用程序链接。商业使用需要单独许可；禁止反向工程、修改、重新分发修改版本以及删除版权声明。

#### 署名要求

```
本软件使用 eCapture Decryptor 库
版权所有 (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com)
授权用于非商业用途
https://github.com/gojue/ecapture_decryptor
```

#### 商业许可

如需商业使用，请发送邮件至 **cfc4n.cs@gmail.com**，主题为 `Commercial License Inquiry - eCapture Decryptor`。

- **[LICENSE](LICENSE)** — 完整许可证（中英文）
- **[LICENSE-BINARY](LICENSE-BINARY)** — 二进制库许可证（中英文）
- **[COPYRIGHT](COPYRIGHT)** — 版权声明
- **[许可摘要](docs/LICENSE-SUMMARY.md)** — 快速参考

# 贡献

由于源代码为专有软件，暂不接受外部贡献。如有问题或建议，欢迎提交 Issue。

# 致谢

本项目基于以下优秀的开源项目：

- [gopacket](https://github.com/google/gopacket) - 数据包处理
- Go 标准库的 `crypto/tls` 包

---

> [!IMPORTANT]
> 1. 使用本工具需要有合法的 SSLKEYLOG 文件。
> 2. 请确保你有权限解密目标流量。
> 3. 遵守所有适用的法律法规。
> 4. 商业使用需要获得单独授权。

**版权所有 © 2024-2026 CFC4N。保留所有权利。**
