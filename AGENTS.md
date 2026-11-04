# AI Agent 工作指引

适用范围：整个仓库。本文说明项目事实和开发约束；机器地址、账号及认证信息只保存在被 Git 忽略的 `AGENTS.local.md`。

## 强制规则：精简变更，非必要不新增

- **代码开发必须保持精简变更，非必要不新增。** 优先修改现有实现，复用现有文件、接口、工具和测试结构。
- 仅修改当前任务必需的内容。不要顺手重构、全仓格式化、升级依赖、修改版本号或修复无关问题。
- 新增文件、依赖、抽象、配置、公共 API 或测试前，先判断现有结构能否承载；只有确有必要时才新增，并说明原因。简单文档修改不新增测试。
- 修改行为时优先在现有测试中补充有价值的回归场景；不写仅重复实现逻辑的测试，不靠跳过测试或降低断言掩盖问题。
- 开始前检查 `git status --short --branch`；保留用户已有改动和未跟踪文件。不得用 `git reset --hard`、`git clean` 等清理未知工作。
- 完成后检查 diff，说明实际变更、验证结果和未验证项；没有运行的检查不能声称通过。

## 先读什么

1. 本文件；涉及本机、SSH、Linux VM 或重新抓包时，再读取根目录 `AGENTS.local.md`（若存在）。它不会因为命名就被所有 Agent 自动加载，不要将其原文回显到日志或回答。
2. `README.md` / `README-zh_Hans.md`：用途与基本入口。
3. `docs/API.md`，特别是 `DecryptPcapngStreamWithOptions / WithOptions`：输出、背压、诊断、期限与资源上限契约。
4. 对应实现与测试；环境和命令以 `go.mod`、实际 `Makefile`、`.github/workflows/ci.yml` 为准。

历史文档中存在过期版本要求和示意接口；若与源码冲突，以当前实现及测试为准，不要照搬 `docs/ARCHITECTURE.md` 中的伪代码。

## 项目作用与使用环境

- Go module 与根包：`github.com/gojue/ecapture_decryptor` / `ecapture_decryptor`。
- 这是 TLS 1.2/1.3、QUIC 流量的解密和应用协议解析 SDK。输入为已有 pcap/pcapng 文件或捕获数据流，以及匹配的 NSS SSLKEYLOG 密钥。密钥可来自外部 reader、pcapng 内嵌 TLS Decryption Secrets Block（DSB），或两者共同提供。
- SDK 输出 `types.DecryptedPacket`，默认解析 HTTP/1.0、HTTP/1.1、HTTP/2、HTTP/3、WebSocket。HAR/JSON 转换由示例或调用方负责，不应移入核心解密层。
- 可直接嵌入 Go 程序，也可通过 `capi/` 构建 C 静态库/动态库；CLI 位于 `examples/go_demo/`，不是根目录的 `main` 包。
- 已有抓包的解密、构建和回归测试可在 macOS/Linux 上运行，不要求 root、eBPF 或在线连接原始抓包目标。当前核心读取路径使用 `gopacket/pcapgo`，不依赖 libpcap 开发库。
- Linux VM 用于运行独立的 eCapture、tcpdump 和流量发生器，重新生成真实夹具。eCapture/eBPF 抓包所需内核与权限属于采集端环境，不是 SDK 离线运行前提。

## 代码地图与数据流

```text
pcap/pcapng + 外部 SSLKEYLOG / 内嵌 DSB
  -> api.go / pcapng_stream.go（读取、密钥导入、连接路由）
  -> TCP 序号重组 -> TLS 解密，或 UDP -> QUIC 包/流重组解密
  -> protocol/ 应用消息解析，或显式 raw stream 输出
  -> types.DecryptedPacket -> 调用方 / 示例 JSON、HAR 导出
```

| 位置 | 职责与修改入口 |
| --- | --- |
| `api.go` | 文件/reader API、`DecryptorConfig`、`DecryptorEngine`、正反向连接路由与连接代次 |
| `pcapng_stream.go` | 可取消的增量 pcapng API、完整块校验、末尾 DSB 观察、回调排空 |
| `tcp_reassembly.go`、`lifecycle.go` | TCP 乱序/重传去重、连接空闲回收 |
| `factory.go` | 按 `tcp` / `udp` 注册解密器、传递选项 |
| `crypto/` | NSS keylog、密钥更新广播、TLS 握手/记录解密、密码套件、输入缓冲 |
| `transport/tls*.go` | TLS 双向处理、密钥等待、协议识别与 raw 输出 |
| `transport/quic*.go` | QUIC 头部保护、包号空间、CRYPTO/STREAM 重组、迟到密钥重试 |
| `protocol/` | HTTP/1.x、HTTP/2 HPACK、HTTP/3 QPACK、WebSocket 解析 |
| `types/` | `Decryptor`、`ProtocolDetector`、`StreamParserInterface`、公共选项和数据模型 |
| `capi/main.go` | C 导出函数、错误缓冲、JSON 包装和字符串释放 |
| `examples/go_demo/` | CLI、JSON/HAR 转换及转换器测试 |
| `examples/go_static_demo/` | 与 C demo 相似的 Go 示例，实际直接调用 Go API，并未链接 Go c-archive |
| `examples/c_demo/`、`examples/test_e2e.py` | C 调用示例及所有示例的真实抓包端到端检查 |
| `test/fixtures/`、`test/testdata/` | 流量发生器、抓包复现步骤、真实抓包与匹配测试密钥 |

协议扩展应使用真实的 `types.ProtocolDetector` / `StreamParserInterface` 和 `protocol.RegisterProtocol(detector)`；密码套件注册入口是 `crypto.RegisterCipherSuite`。不要根据旧文档另建一套接口。

## 不可破坏的行为契约

- `DecryptPcapFile` / `DecryptWithConfig` 接受可选外部 keylog，仍需加载 DSB。可 seek 的 pcapng 会先扫描 DSB 再读包；不可 seek 的 pcapng 单遍读入并观察 DSB，不得依赖回退 seek。
- `DecryptLiveTraffic` 接收调用方提供的 `io.Reader`，本身不会打开网卡。增量 pcapng 优先使用 `DecryptPcapngStream(ctx, io.ReadCloser, emit)`；该入口只接受 pcapng。
- DSB 可能迟于握手、应用数据，甚至最后一个网络包。QUIC 必须由密钥更新唤醒重试，不依赖下一包或 EOF；TLS/QUIC 均需保留有界的等待和缓存。
- TCP 按序号重组并消除重传/回环重复包；同一四元组的新 SYN 创建新 `Generation`，重复 SYN 不创建新连接。双向数据归入同一连接，QUIC Initial 自带有效握手负载，不能丢弃。
- channel API 的输出必须由调用方并发消费，函数返回后再由调用方关闭 channel。流 API 的 `emit` 串行调用；回调报错会停止输入，生产者仍需排空退出。
- `input.Close()` 必须能中断阻塞读取。取消 context 无法中断调用方永久阻塞的 `emit`；保持背压，不使用无限队列或随意丢弃输出规避阻塞。
- `RawChunks` 默认关闭；开启后输出已认证的 TLS 字节或连续 QUIC STREAM 字节，与应用解析互斥。chunk 不是应用消息；`offset`、`stream_id`、`stream_end` 的含义见 `docs/API.md`。
- `OnDiagnostic` 可并发执行，必须及时返回且不能重入引擎。诊断仅含连接、阶段和固定原因码，不加入密钥、明文或底层 parser 错误文本；诊断不能替代终止错误返回。
- 默认 `KeyWaitTimeout=30s`、`IdleTimeout=5min`、`MaxConnections=1024`；非正值使用默认值。期限依据实际时间，不能使用抓包时间戳；连接额度包括仍在退出的 worker。
- 保持现有缓存上限和关闭语义；退出需释放路由、队列、解析器引用与连接额度，正常 EOF 需处理已缓冲数据。不得通过删除限制、无界等待或持有路由锁执行阻塞关闭修复问题。
- `DecryptedPacket.Data` 带 `json:"-"`：直接 JSON 编码不会自动携带明文正文。Go CLI 的显式转换器与 C API 的 JSON 输出行为不同，修改时同时检查消费者预期。

HTTP/3 需要包含客户端 Initial/ClientHello 的双向 UDP 抓包和匹配 TLS 1.3 secrets。真实夹具验证 QUIC v1/v2 的 AES-128-GCM 双向多次 Key Update；AES-256-GCM/ChaCha20 更新仅有向量和状态测试，draft-29 未通过真实抓包验证。QUIC 每方向保留当前/上一代及下一代候选，详见 `docs/API.md`。独立 aioquic 夹具覆盖 v1/v2 × 三套件的握手/应用解密、CID 轮换/迁移、Retry/VN 和 accepted/rejected 0-RTT（不扩大 Key Update 的实测套件范围）；零长度 CID 仅在唯一原 tuple 路由，early data 输出边界见 API 文档。HTTP/3 已支持有界动态 QPACK、控制流、1xx/final/trailers、push 和 RESET_STREAM；双向动态 QPACK 的独立真实夹具使用 QUIC v1。decoder feedback 仅被动读取，不发送 ACK；消息与资源契约见 API 文档。不要宣称已支持 TLS KeyUpdate、DATAGRAM 或 STARTTLS。C 的 `DecryptLiveTrafficToFile` 网卡接入仍是占位实现，E2E 验证其错误路径。

## 编译环境与命令

- 使用 Go **1.26.0 或兼容的更新版本**；根模块、HTTP/3 fixture 子模块和 CI 当前均以 1.26 为基准。`docs/DEVELOPMENT.md` 的 Go >=1.21 和 `scripts/build-multiplatform.sh` 的 `golang:1.21` 镜像已过时。
- 保留 `go.mod` 中 `github.com/google/gopacket v1.1.19 => github.com/cfc4n/gopacket v1.1.20` 的 replace；当前 DSB 读取依赖该 fork，不能随手换回上游。
- Go SDK/CLI 可关闭 CGO；C archive/shared 和 `-race` 需要可用 C 编译器与 `CGO_ENABLED=1`。macOS 使用 Xcode Command Line Tools/Clang，Linux 使用 GCC/Clang（通常由 `build-essential` 提供）。
- Make 用于构建；Python 3 用于 `examples/test_e2e.py`。`goimports`、`golangci-lint` 用于代码检查。先检查已安装工具，不因文档任务自动安装或升级。

以下命令均从仓库根目录执行：

```sh
go version
go env GOOS GOARCH CGO_ENABLED CC
go mod download                         # 首次准备且需要下载依赖时
go test ./...                           # 常规回归
CGO_ENABLED=1 go test -race ./...        # 并发/生命周期修改及完整验证
make build-static                      # lib/libecapture_decryptor.a + include/*.h
make build-shared                      # macOS .dylib，Linux .so
make -C examples/go_demo build          # bin/ecapture_decryptor
make -C examples/c_demo all             # C 示例，使用静态库
make -C examples/go_static_demo build   # bin/go_static_decryptor
make -C examples test                   # Python 构建并验证 Go/C 全部示例
```

根目录默认 `make` 只构建静态库；`make build` 按序构建静态库和动态库。两种构建共用生成头文件，不要并发执行。生成的 `lib/`、`include/`、`bin/`、`dist/` 不提交；不要手改生成头文件。核心或 C API 有修改后，应先重建静态库再构建 C 示例，避免复用旧 `.a`。

```sh
# 无外部 keylog，使用夹具内嵌 DSB
./bin/ecapture_decryptor -pcap test/testdata/http2_multiplex_ecapture_dsb.pcapng

# 外部 keylog + HAR 导出
mkdir -p test/result
./bin/ecapture_decryptor \
  -pcap test/testdata/http11_keepalive_chunked_tcpdump_no_dsb.pcapng \
  -sslkeylog test/testdata/http11_keepalive_chunked_tcpdump.keys \
  -har test/result/http11.har
```

CGO 跨平台编译必须同时配置目标 C 工具链，不能只设置 `GOOS/GOARCH`。发布工作流当前覆盖 Linux amd64/arm64 与 Darwin arm64；Linux arm64 交叉编译使用 `aarch64-linux-gnu-gcc`。不要将其写成已验证 Windows 或 Darwin amd64 发布。

## 按变更范围验证

| 修改范围 | 优先验证 |
| --- | --- |
| `crypto/` | `go test ./crypto`；相关 TLS/QUIC 解密测试 |
| `protocol/`、HAR/JSON | `go test ./protocol ./examples/go_demo`；对应真实抓包 E2E |
| 根 API、重组、连接生命周期、`transport/` | `CGO_ENABLED=1 go test -race ./...`，重点检查取消、EOF、迟到 DSB、资源释放 |
| `capi/`、构建、示例 | `make build` 与 `make -C examples test` |
| 仅文档/忽略规则 | 检查内容、路径、命令及 `git diff --check`；不新增测试 |

真实夹具回归可单独运行：

```sh
go test -run 'TestDecryptTCPHTTPCaptures|TestDecryptHTTP3QUICCapture|TestDecryptPcapngStreamCapturedTraffic' -v .
```

关键回归入口还包括 `quic_late_dsb_test.go`、`raw_stream_test.go`、`connection_routing_test.go`、`lifecycle_test.go` 和 `transport/*_lifecycle_test.go`。E2E 默认在临时目录生成产物并自动删除；需保留输出时使用 `python3 examples/test_e2e.py --output-dir test/result`。避免运行会重写已跟踪 `examples/go_static_demo/output_go_static.json` 的单示例 test 目标。

CI 在 Ubuntu/macOS 上运行 `go test -v -race -coverprofile=coverage.out -covermode=atomic ./...`、静态/动态库构建和示例 E2E，并检查 gofmt、goimports、golangci-lint。局部代码修改只格式化涉及的 Go 文件；根 `make fmt` 会写整个仓库。`make check` 的格式检查只打印差异，不能仅凭退出码断言格式正确；要确认格式工具输出为空。`make tools` 固定 goimports v0.49.0、golangci-lint v1.64.8，以 `CGO_ENABLED=0` 构建工具；SDK 的 race/C 构建仍需 CGO。

## Linux VM 与真实夹具

- VM 的连接、认证与本机专用路径见 `AGENTS.local.md`；它必须保持 Git 忽略，且权限设为 `600`。不要把 VM 凭据复制到可提交文件、提交信息、PR、日志或示例命令中。
- 普通离线回归直接使用已提交的 `test/testdata/`。重新抓包时按照 `test/fixtures/http_tcp_capture/README.md` 和 `test/fixtures/http3_capture/README.md` 操作，在 VM 上先启动抓包，再运行客户端。
- HTTP/1.0、HTTP/1.1 keep-alive/chunked、HTTP/2 multiplex 的回环 TCP 端口分别为 44434、44435、44436；HTTP/3 回环 UDP 端口为 44433。这里 HTTP/1.0 指应用协议，TCP 夹具实际协商 TLS 1.3。
- `test/fixtures/http3_capture/` 是独立 Go module（使用 quic-go），根目录的 `go test ./...` 不覆盖它；修改发生器时进入该目录单独构建/验证。生产 SDK 不依赖整个 quic-go。
- HTTP/3 抓包需 `QUIC_GO_DISABLE_GSO=true`；公网抓包先查实际出口网卡和目标地址，不硬编码旧 IP。
- 真实夹具来自 tcpdump/eCapture；流量发生器只产生网络流量。`editcap` 转换容器格式，不应伪造网络包替代真实抓包。新增夹具要配套匹配 keylog 或 DSB、复现步骤和必要断言。
- 抓包可能含回环重复包；保持去重与一条逻辑连接的断言。外部 SSLKEYLOG、内嵌 DSB、不可 seek 输入、迟到 DSB 都是需要保留的覆盖路径。

## 发布与文档维护

- API/支持范围变化时只同步相关说明：`docs/API.md`、两种语言的 README 和受影响示例。
- 普通开发不运行 `make release` / `scripts/release.sh`：它会清理构建目录并修改 `capi/main.go` 版本字符串。`scripts/version.sh` 仍匹配旧字符串 `ecapture_decryptor v...`，与当前 `GetVersion()` 的 `eCapture Decryptor v...` 不一致，发布前需核对，不能盲信脚本成功消息。
- 保留已有版权头及许可证文件；涉及授权说明以仓库 `LICENSE`、`LICENSE-BINARY`、`COPYRIGHT` 为依据，不自行改写条款。
