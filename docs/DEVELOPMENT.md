# Development Guide - 开发指南

本文档面向 ecapture_decryptor 的开发者和贡献者。

## 🛠️ 开发环境设置

### 必需工具

| 工具 | 版本要求 | 用途 |
|------|---------|------|
| Go | >= 1.21 | 编译和构建 |
| Git | >= 2.0 | 版本控制 |
| Make | >= 3.81 | 构建自动化 |
| GCC/Clang | 任意 | C 示例编译 |

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
│   └── stream.go            # 流密码操作
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
│   └── go_static_demo/      # Go CGO 示例
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

# 构建所有
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
# 构建并测试示例
cd examples && make test
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

# 测试覆盖率
go test -cover ./...
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### 编写测试

#### 单元测试示例

```go
// crypto/keylog_test.go
func TestKeyLogStore(t *testing.T) {
    keylog := strings.NewReader(`
CLIENT_RANDOM abcd1234... master_secret_data
`)
    
    store, err := NewKeyLogStore(keylog)
    assert.NoError(t, err)
    assert.NotNil(t, store)
    
    // 测试密钥查找
    key, found := store.GetKey("abcd1234...")
    assert.True(t, found)
    assert.NotNil(t, key)
}
```

#### 集成测试示例

```go
// api_test.go
func TestDecryptPcapFile(t *testing.T) {
    keylog, _ := os.Open("test/testdata/sslkey.log")
    pcap, _ := os.Open("test/testdata/traffic.pcap")
    defer keylog.Close()
    defer pcap.Close()
    
    packets := make(chan *types.DecryptedPacket, 100)
    
    go func() {
        err := DecryptPcapFile(keylog, pcap, packets)
        assert.NoError(t, err)
        close(packets)
    }()
    
    count := 0
    for packet := range packets {
        count++
        assert.NotEmpty(t, packet.Protocol)
        assert.NotEmpty(t, packet.Direction)
    }
    
    assert.Greater(t, count, 0)
}
```

### 测试数据

测试数据位于 `test/testdata/` 目录：

```
test/testdata/
├── all_clients.pcap           # 多客户端测试数据
├── all_clients_sslkey.log     # 对应的密钥日志
├── cc.pcapng                  # 单个连接测试
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

1. **创建解析器文件**

```go
// protocol/protocol_grpc.go
package protocol

import "github.com/gojue/ecapture_decryptor/types"

type GRPCParser struct {
    // 状态
}

func NewGRPCParser() *GRPCParser {
    return &GRPCParser{}
}

func (p *GRPCParser) Parse(data []byte, direction string) ([]*types.DecryptedPacket, error) {
    // 解析逻辑
    return packets, nil
}

func (p *GRPCParser) GetProtocolName() string {
    return "grpc"
}
```

2. **注册协议**

```go
// protocol/protocol_registry.go
func init() {
    RegisterProtocol("grpc", NewGRPCParser())
}
```

3. **添加测试**

```go
// protocol/protocol_grpc_test.go
func TestGRPCParser(t *testing.T) {
    parser := NewGRPCParser()
    data := []byte("gRPC data...")
    
    packets, err := parser.Parse(data, "request")
    assert.NoError(t, err)
    assert.Greater(t, len(packets), 0)
}
```

### 添加新的密码套件

1. **实现解密函数**

```go
// crypto/decryptor.go
func decryptAES256GCM(key, nonce, ciphertext, aad []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    
    return gcm.Open(nil, nonce, ciphertext, aad)
}
```

2. **注册密码套件**

```go
// crypto/cipher_registry.go
func init() {
    RegisterCipher(0x1302, "TLS_AES_256_GCM_SHA384", decryptAES256GCM)
}
```

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
# 生成内存 profile
go test -memprofile=mem.prof ./...

# 分析
go tool pprof mem.prof
```

#### CPU 性能

```bash
# 生成 CPU profile
go test -cpuprofile=cpu.prof ./...

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
git checkout -b feature/add-grpc-support

# 或修复分支
git checkout -b fix/memory-leak
```

### 3. 开发和测试

```bash
# 编写代码
vim protocol/protocol_grpc.go

# 添加测试
vim protocol/protocol_grpc_test.go

# 运行测试
go test ./protocol/

# 格式化代码
make fmt

# 静态检查
make lint
```

### 4. 提交更改

```bash
# 添加文件
git add protocol/protocol_grpc.go protocol/protocol_grpc_test.go

# 提交（遵循 conventional commits）
git commit -m "feat(protocol): add gRPC protocol parser

- Implement gRPC frame parsing
- Add unit tests
- Update documentation

Closes #123"
```

### 5. 推送和创建 PR

```bash
# 推送到你的 fork
git push origin feature/add-grpc-support

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

```yaml
# .github/workflows/test.yml
name: Test
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.26'
      - run: make test
      - run: make lint
```

### 发布工作流

```yaml
# .github/workflows/release.yml
name: Release
on:
  push:
    tags:
      - 'v*'
jobs:
  release:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
      - run: make release VERSION=${{ github.ref_name }}
      - uses: softprops/action-gh-release@v1
        with:
          files: dist/*.tar.gz
```

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
# 检查链接
find docs -name "*.md" -exec grep -H "http" {} \;

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

