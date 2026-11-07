# Development Guide - 开发指南

本文档面向 ecapture_decryptor 的开发者和贡献者。

## 🛠️ 开发环境设置

### 必需工具

| 工具 | 版本要求 | 用途 |
|------|---------|------|
| Go | >= 1.26.0 | 与根模块及 CI 的 Go 1.26 基线一致 |
| Git | >= 2.0 | 版本控制 |
| Make | >= 3.81 | 构建自动化 |
| GCC/Clang | 支持当前目标平台 | C archive/shared、C 示例及 `-race` 构建 |
| Python | 3 | 示例端到端测试 |

Go SDK/CLI 可使用 `CGO_ENABLED=0`；C 库和 race 检查需要 `CGO_ENABLED=1`
及可用 C 编译器。离线读取使用 `pcapgo`，不要求 libpcap 开发库、root 或 eBPF。

### 可选工具

| 工具 | 用途 |
|------|------|
| golangci-lint | 代码静态检查 |
| goimports | 代码格式化 |
| Docker | 多平台构建 |

### 安装依赖

```bash
# 克隆项目
git clone https://github.com/gojue/ecapture_decryptor.git
cd ecapture_decryptor

# 安装 Go 依赖
go mod download

# 安装开发工具
make tools
```

`make tools` 固定安装 goimports v0.49.0、golangci-lint v1.64.8，安装工具时
使用 `CGO_ENABLED=0`；这不改变 SDK 的 race/C 构建要求。保留 `go.mod` 中
gopacket 的 replace，pcapng DSB 读取依赖该 fork。

---

## 📂 项目结构

```
ecapture_decryptor/
├── api.go                    # 公开 API
├── factory.go                # 解密器工厂
├── api_test.go               # API 测试
│
├── crypto/                   # 密码学模块
│   ├── keylog.go            # SSLKEYLOG 解析
│   ├── cipher_registry.go   # 密码套件注册
│   ├── decryptor.go         # 通用解密器
│   ├── handshake.go         # TLS 握手解析
│   └── stream.go            # TLS 输入记录缓冲
│
├── transport/                # 传输层解密
│   ├── adapters.go          # 适配器接口
│   ├── tlsdecryptor.go      # TLS 解密器
│   ├── tls_wrapper.go       # TLS 包装器
│   └── quic_decryptor.go    # QUIC 解密器
│
├── protocol/                 # 协议解析
│   ├── protocol_registry.go # 协议注册中心
│   ├── http_stream.go       # HTTP/1.1 解析
│   ├── protocol_http2.go    # HTTP/2 解析
│   ├── protocol_http3.go    # HTTP/3 解析
│   └── protocol_websocket.go# WebSocket 解析
│
├── types/                    # 类型定义
│   ├── interfaces.go        # 公共接口
│   └── packet.go            # 数据包类型
│
├── capi/                     # C API
│   └── main.go              # CGO 导出
│
├── examples/                 # 示例程序
│   ├── c_demo/              # C 语言示例
│   ├── go_demo/             # Go 语言示例
│   └── go_static_demo/      # 直接调用 Go API 的示例，未链接 C archive
│
├── docs/                     # 文档
│   ├── API.md               # API 参考
│   ├── ARCHITECTURE.md      # 架构文档
│   ├── DEVELOPMENT.md       # 本文档
│   └── ...
│
├── scripts/                  # 脚本
│   ├── release.sh           # 发布脚本
│   ├── version.sh           # 版本管理
│   └── add_copyright.sh     # 版权添加
│
├── test/                     # 测试数据
│   └── testdata/            # 测试文件
│
├── Makefile                  # 构建脚本
├── go.mod                    # Go 模块定义
├── go.sum                    # 依赖锁定
├── README.md                 # 项目主页
├── CHANGELOG.md              # 版本历史
└── LICENSE                   # 许可证
```

---

## 🚀 快速开始

### 构建项目

```bash
# 构建静态库
make build-static

# 构建动态库
make build-shared

# 按序构建两种库（共用生成头文件，不使用 make -j）
make build

# 运行测试
make test

# 代码格式化
make fmt

# 静态检查
make lint
```

### 运行示例

```bash
# 构建 CLI；根目录是 SDK 包，不是 main 包
make -C examples/go_demo build

# 重建 C 静态库并构建、测试全部示例
make build-static
make -C examples test
```

---

## 🧪 测试

### 运行单元测试

```bash
# 运行所有测试
go test ./...

# 运行特定包的测试
go test ./crypto/
go test ./transport/
go test ./protocol/

# 详细输出
go test -v ./...

# 并发与生命周期检查（与 CI 一致）
CGO_ENABLED=1 go test -race ./...

# 测试覆盖率
go test -cover ./...
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### 编写测试

#### 单元测试示例

```go
// crypto 包内示例，需要 bytes、encoding/hex、strings、testing。
func TestKeyLogLookup(t *testing.T) {
    random := bytes.Repeat([]byte{1}, 32)
    master := bytes.Repeat([]byte{2}, 48)
    line := "CLIENT_RANDOM " + hex.EncodeToString(random) + " " + hex.EncodeToString(master)
    store, err := NewKeyLogStoreFromReader(strings.NewReader(line))
    if err != nil {
        t.Fatal(err)
    }
    secrets := store.GetSecrets(random)
    if secrets == nil || !bytes.Equal(secrets.MasterSecret, master) {
        t.Fatal("master secret lookup failed")
    }
}
```

#### 集成测试示例

```go
// 根包内示例，需要 os、testing 及本模块的 types 包。
func TestCapturedHTTP(t *testing.T) {
    keylog, err := os.Open("test/testdata/all_clients_sslkey.log")
    if err != nil {
        t.Fatal(err)
    }
    defer keylog.Close()
    pcap, err := os.Open("test/testdata/all_clients.pcap")
    if err != nil {
        t.Fatal(err)
    }
    defer pcap.Close()

    packets := make(chan *types.DecryptedPacket)
    done := make(chan error, 1)
    go func() {
        done <- DecryptPcapFile(keylog, pcap, packets)
        close(packets)
    }()

    count := 0
    for range packets {
        count++
    }
    if err := <-done; err != nil {
        t.Fatal(err)
    }
    if count == 0 {
        t.Fatal("no decrypted packets")
    }
}
```

channel 必须与解密并发消费；由调用方在函数返回后关闭。实际回归还应验证
协议、方向、连接身份和完整明文，参考 `http_tcp_integration_test.go`。

### 测试数据

测试数据位于 `test/testdata/` 目录：

```
test/testdata/
├── all_clients.pcap           # 多客户端测试数据
├── all_clients_sslkey.log     # 对应的密钥日志
├── http10_tcpdump_no_dsb.pcapng # 独立 TLS HTTP/1.0 抓包
└── ...
```

---

## 📝 代码规范

### Go 代码风格

遵循 [Effective Go](https://golang.org/doc/effective_go.html) 和 [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)。

#### 命名规范

```go
// 好的命名
type DecryptorConfig struct {}
func NewDecryptorConfig() *DecryptorConfig {}
var ErrInvalidKeyLog = errors.New("invalid keylog")

// 避免
type decryptor_config struct {}  // 不要使用下划线
func new_decryptor() {}           // 不要使用下划线
var err1 = errors.New("error")    // 错误变量要有意义
```

#### 注释规范

```go
// DecryptPcapFile 解密 PCAP 文件中的流量。
//
// 参数：
//   keylogReader: SSLKEYLOG 文件读取器
//   pcapFileHandle: PCAP 文件读取器
//   packetChan: 输出通道
//
// 返回：
//   error: 错误信息，成功返回 nil
func DecryptPcapFile(
    keylogReader io.Reader,
    pcapFileHandle io.Reader,
    packetChan chan *types.DecryptedPacket,
) error {
    // 实现
}
```

#### 错误处理

```go
// 好的错误处理
if err := doSomething(); err != nil {
    return fmt.Errorf("failed to do something: %w", err)
}

// 自定义错误
var (
    ErrInvalidPcap   = errors.New("invalid pcap format")
    ErrNoValidKeys   = errors.New("no valid keys found")
    ErrChannelClosed = errors.New("packet channel closed")
)
```

### 代码格式化

```bash
# 格式化代码
make fmt

# 或手动运行
gofmt -s -w .
goimports -w .
```

以上命令会格式化整个仓库；局部修改只对涉及的文件运行 gofmt/goimports。
`make check` 会打印格式差异并运行 lint，格式工具输出必须为空，不能只看退出码。

### 静态检查

```bash
# 运行 linter
make lint

# 或手动运行
golangci-lint run
```

---

## 🏗️ 添加新功能

### 添加新的协议解析器

先查看 [真实接口](../types/interfaces.go) 与
[协议注册实现](../protocol/protocol_registry.go)。解析器按方向增量接收字节，
通过创建时传入的 channel 输出 `*types.DecryptedPacket`，不是返回消息切片：

```go
// types 包的接口签名；类型位于 types/interfaces.go。
type StreamParserInterface interface {
    FeedRequest(data []byte)
    FeedResponse(data []byte)
    SetPacketTime(t time.Time)
    Flush()
}

type ProtocolDetector interface {
    Name() string
    Detect(data []byte) int
    CreateParser(addr ConnectionKey, packetChan chan *DecryptedPacket) StreamParserInterface
}
```

1. 实现 `types.StreamParserInterface`，保持有界缓存、分片/合并消息处理和输出背压。
2. 实现 `types.ProtocolDetector`，由 `CreateParser` 为每条连接创建独立解析器，
   然后调用 `protocol.RegisterProtocol(detector)`。自动检测选择最高正分；
   无法安全识别的协议应采用显式选择，公共选项的校验和传输路由也需配套修改。
3. 在现有协议测试结构中验证完整字节、双向状态、截断、资源上限及关闭行为，
   再补独立真实抓包回归。可参考 `protocol/http_stream_test.go`。

gRPC 已在 HTTPEvents 的 HTTP/2 路径中实现；不要另建基于任意字节前缀的
独立 gRPC 检测器。HTTP/3 由 QUIC 路径处理，不能仅靠注册 TLS 字节检测器接入。

### 添加新的密码套件

注册入口是 `crypto.RegisterCipherSuite(config *crypto.CipherSuiteConfig)`，见
[`crypto/cipher_registry.go`](../crypto/cipher_registry.go)。配置包含 ID、名称、
TLS 版本、key/MAC/IV 长度、哈希函数，以及 AEAD 套件的 `AEADFactory`。
先核对已有配置，AES-256-GCM 已内置，不要重复注册示例套件。

注册不会自动实现新算法、记录布局或 TLS/QUIC 状态。需要修改解密路径时，
同时验证版本与套件匹配、独立密码向量、认证失败不输出及真实对端互通。

---

## 🐛 调试

### 启用详细日志

```go
logger := log.New(os.Stdout, "[DEBUG] ", log.LstdFlags|log.Lshortfile)

config := ecapture_decryptor.NewDecryptorConfig().
    WithSSLKeyLog(keylog).
    WithPcapReader(pcap).
    WithPacketChan(packets).
    WithLogger(logger)

err := ecapture_decryptor.DecryptWithConfig(config)
```

### 使用 Delve 调试器

```bash
# 安装 Delve
go install github.com/go-delve/delve/cmd/dlv@latest

# 调试测试
dlv test ./crypto

# 调试程序
dlv debug ./examples/go_demo
```

### 常见问题排查

#### 解密失败

```bash
# 检查 keylog 格式
cat sslkey.log | head -5

# 验证 PCAP 文件
tcpdump -r traffic.pcap -c 5
```

#### 内存泄漏

```bash
# 每次选择一个包，避免多包共用 profile 输出文件
go test -memprofile=mem.prof ./protocol

# 分析
go tool pprof mem.prof
```

#### CPU 性能

```bash
# 每次选择一个包
go test -cpuprofile=cpu.prof ./protocol

# 分析
go tool pprof cpu.prof
```

---

## 📚 开发工作流

### 1. Fork 和克隆

```bash
# Fork 项目到你的账号
# 然后克隆
git clone https://github.com/YOUR_USERNAME/ecapture_decryptor.git
cd ecapture_decryptor

# 添加上游仓库
git remote add upstream https://github.com/gojue/ecapture_decryptor.git
```

### 2. 创建分支

```bash
# 创建功能分支
git checkout -b feat/add-protocol

# 或修复分支
git checkout -b fix/memory-leak
```

### 3. 开发和测试

```bash
# 编写代码
vim protocol/protocol_custom.go

# 添加测试
vim protocol/protocol_custom_test.go

# 运行测试
go test ./protocol/

# 格式化代码
gofmt -w protocol/protocol_custom.go protocol/protocol_custom_test.go
goimports -w protocol/protocol_custom.go protocol/protocol_custom_test.go

# 静态检查
make lint
```

### 4. 提交更改

```bash
# 添加文件
git add protocol/protocol_custom.go protocol/protocol_custom_test.go

# 提交（遵循 conventional commits）
git commit -m "feat(protocol): add custom protocol parser

- Implement bounded incremental parsing
- Add unit tests
- Update documentation

Closes #123"
```

### 5. 推送和创建 PR

```bash
# 推送到你的 fork
git push origin feat/add-protocol

# 在 GitHub 上创建 Pull Request
```

---

## 📦 发布流程

### 准备发布

```bash
# 1. 更新版本号
./scripts/version.sh bump minor

# 2. 更新 CHANGELOG
vim CHANGELOG.md

# 3. 运行完整测试
make test
make lint

# 4. 提交更改
git add .
git commit -m "Release v1.1.0"
```

### 创建发布

```bash
# 1. 创建标签
git tag v1.1.0

# 2. 推送标签（触发 CI/CD）
git push origin v1.1.0

# 3. GitHub Actions 自动构建并发布
```

### 手动构建发布包

```bash
# 本地构建
make release VERSION=v1.1.0

# 查看构建产物
ls -la dist/
```

---

## 🔧 CI/CD

项目使用 GitHub Actions 进行自动化构建和测试。

### 工作流

实际配置是 [`.github/workflows/ci.yml`](../.github/workflows/ci.yml)，使用 Go 1.26：

- 检查 gofmt/goimports 输出，并运行 golangci-lint。
- Ubuntu/macOS 运行 `go test -v -race -coverprofile=coverage.out -covermode=atomic ./...`。
- 按序构建 C 静态库、动态库，再构建示例并运行 `make -C examples test`。

工具安装与缓存方式以该工作流和根 Makefile 为准，不在文档中维护另一份 YAML。

### 发布工作流

实际配置是 [`.github/workflows/release.yml`](../.github/workflows/release.yml)，
由 `v*.*.*` tag 触发，构建 Linux amd64、Linux arm64 与 Darwin arm64，再上传发布包。
Linux arm64 使用 `aarch64-linux-gnu-gcc` 交叉编译；C 库交叉构建不能只设置
`GOOS/GOARCH`。普通开发验证不运行发布、打 tag 或推送 tag。

---

## 📖 文档

### 更新文档

```bash
# API 文档
vim docs/API.md

# 架构文档
vim docs/ARCHITECTURE.md

# 主 README
vim README.md
```

### 文档构建

```bash
# 列出链接供检查（不验证远端可达性）
rg -n 'https?://' docs --glob '*.md'

# 生成 PDF（需要 pandoc）
pandoc docs/API.md -o docs/API.pdf
```

---

## 🤝 贡献指南

### 提交前检查清单

- [ ] 代码已格式化 (`make fmt`)
- [ ] 所有测试通过 (`make test`)
- [ ] 静态检查通过 (`make lint`)
- [ ] 添加了必要的测试
- [ ] 更新了相关文档
- [ ] 提交信息符合规范

### Commit Message 规范

使用 [Conventional Commits](https://www.conventionalcommits.org/)：

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Type**:
- `feat`: 新功能
- `fix`: Bug 修复
- `docs`: 文档更新
- `style`: 代码格式（不影响功能）
- `refactor`: 代码重构
- `test`: 测试相关
- `chore`: 构建、工具等

**示例**:
```
feat(protocol): add gRPC protocol support

- Implement gRPC frame parsing
- Add protocol detection logic
- Include unit tests

Closes #123
```

---

## 🔗 资源链接

### 外部文档

- [TLS 1.3 RFC](https://tools.ietf.org/html/rfc8446)
- [QUIC RFC](https://tools.ietf.org/html/rfc9000)
- [HTTP/2 RFC](https://tools.ietf.org/html/rfc7540)
- [HTTP/3 RFC](https://tools.ietf.org/html/rfc9114)

### 相关项目

- [gopacket](https://github.com/google/gopacket) - 数据包处理
- [quic-go](https://github.com/quic-go/quic-go) - QUIC 实现

---

## 📞 获取帮助

- 📧 Email: cfc4n.cs@gmail.com
- 🐛 Issues: https://github.com/gojue/ecapture_decryptor/issues
- 💬 Discussions: https://github.com/gojue/ecapture_decryptor/discussions

---

**维护者**: CFC4N (cfc4n.cs@gmail.com)  
**最后更新**: 2026-01-05

