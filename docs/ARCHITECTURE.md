# Architecture - 架构设计文档

本文档描述 ecapture_decryptor 的系统架构和设计原理。

## 📐 架构概览

ecapture_decryptor 采用**分层架构**设计，每层职责清晰，模块解耦。

```
┌─────────────────────────────────────────────────────────────┐
│                     Application Layer                       │
│                      应用程序层                              │
├─────────────────────────────────────────────────────────────┤
│              Public API (api.go)                            │
│              公开 API 接口                                   │
├─────────────────────────────────────────────────────────────┤
│         Protocol Parser Layer (protocol/)                   │
│         协议解析层 - HTTP/1.1, HTTP/2, HTTP/3, WS          │
├─────────────────────────────────────────────────────────────┤
│       Transport Layer Decryption (transport/)               │
│       传输层解密 - TLS 1.2/1.3, QUIC                        │
├─────────────────────────────────────────────────────────────┤
│         Cryptography Layer (crypto/)                        │
│         密码学层 - 密钥管理、加密算法                        │
├─────────────────────────────────────────────────────────────┤
│          Packet Capture (gopacket)                          │
│          数据包捕获和解析                                    │
└─────────────────────────────────────────────────────────────┘
```

---

## 🏗️ 模块设计

### 1. 公开 API 层

**位置**: `api.go`, `factory.go`

**职责**:
- 提供简洁的公开接口
- 管理解密器生命周期
- 协调各层模块

**核心组件**:

```go
// API 入口
func DecryptPcapFile(keylog, pcap io.Reader, output chan) error
func DecryptLiveTraffic(keylog, pcap io.Reader, output chan) error

// 配置构建器
type DecryptorConfig struct {
    sslKeyLogger io.Reader
    pcapReader   io.Reader
    packetChan   chan *types.DecryptedPacket
    logger       *log.Logger
}

// 工厂模式
type DecryptorFactory struct {
    keyLog     *crypto.KeyLogStore
    logger     *log.Logger
    packetChan chan *types.DecryptedPacket
}
```

**设计模式**:
- **Builder 模式**: `DecryptorConfig` 使用链式调用构建配置
- **Factory 模式**: `DecryptorFactory` 按需创建解密器实例

---

### 2. 协议解析层

**位置**: `protocol/`

**职责**:
- 解析应用层协议
- 提取协议元数据
- 重组分片消息

**模块结构**:

```
protocol/
├── protocol_registry.go      # 协议注册中心
├── http_stream.go            # HTTP/1.1 流解析器
├── protocol_http2.go         # HTTP/2 帧解析器
├── protocol_http3.go         # HTTP/3 (QUIC+QPACK) 解析器
└── protocol_websocket.go     # WebSocket 消息解析器
```

**核心接口**:

```go
// 协议解析器接口
type ProtocolParser interface {
    Parse(data []byte, direction string) ([]*types.DecryptedPacket, error)
    GetProtocolName() string
}

// 注册机制
func RegisterProtocol(name string, parser ProtocolParser)
func GetParser(protocol string) ProtocolParser
```

**协议识别流程**:

```
┌──────────────┐
│ 解密数据      │
└──────┬───────┘
       │
       ▼
┌──────────────────┐
│ 协议识别          │
│ - HTTP/1.1        │  识别特征:
│ - HTTP/2          │  - HTTP/1.1: "GET", "POST", "HTTP/"
│ - HTTP/3          │  - HTTP/2: SETTINGS 帧 (0x04)
│ - WebSocket       │  - HTTP/3: SETTINGS 帧 + QPACK
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│ 选择解析器        │
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│ 解析并提取元数据  │
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│ 输出解密包        │
└──────────────────┘
```

---

### 3. 传输层解密

**位置**: `transport/`

**职责**:
- TLS 1.2/1.3 解密
- QUIC 解密
- 连接状态管理

**模块结构**:

```
transport/
├── adapters.go           # 适配器接口
├── tlsdecryptor.go       # TLS 解密器
├── tls_wrapper.go        # TLS 包装器
└── quic_decryptor.go     # QUIC 解密器
```

**核心接口**:

```go
// 解密器接口 (types/interfaces.go)
type Decryptor interface {
    Decrypt(packet gopacket.Packet) error
    GetProtocol() string
    Close() error
}

// 连接工厂接口
type DecryptorFactory interface {
    CreateDecryptor(connKey types.ConnectionKey) types.Decryptor
}
```

**TLS 解密流程**:

```
┌─────────────────┐
│ TCP 数据包       │
└────────┬────────┘
         │
         ▼
┌─────────────────────┐
│ 识别 TLS 握手        │
│ - ClientHello       │
│ - ServerHello       │
│ - ChangeCipherSpec  │
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│ 从 KeyLog 查找密钥  │
│ - CLIENT_RANDOM     │
│ - 客户端/服务器密钥  │
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│ 解密 TLS 记录        │
│ - 计算 IV/Nonce     │
│ - AES-GCM/ChaCha20  │
│ - 验证 MAC          │
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│ 输出明文数据         │
└─────────────────────┘
```

**QUIC 解密流程**:

```
┌─────────────────┐
│ UDP 数据包       │
└────────┬────────┘
         │
         ▼
┌─────────────────────┐
│ 解析 QUIC 头部       │
│ - Long Header       │
│ - Short Header      │
│ - Packet Number     │
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│ 从 KeyLog 查找密钥  │
│ - QUIC_CLIENT       │
│ - QUIC_SERVER       │
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│ 解密 QUIC Payload   │
│ - 头部保护移除       │
│ - Payload 解密      │
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│ 重组 QUIC 帧         │
│ - STREAM 帧         │
│ - CRYPTO 帧         │
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│ 输出 HTTP/3 数据     │
└─────────────────────┘
```

---

### 4. 密码学层

**位置**: `crypto/`

**职责**:
- 密钥管理
- 加密算法实现
- 握手信息解析

**模块结构**:

```
crypto/
├── keylog.go             # SSLKEYLOG 解析和存储
├── cipher_registry.go    # 密码套件注册
├── decryptor.go          # 通用解密器
├── handshake.go          # TLS 握手解析
└── stream.go             # 流密码操作
```

**密钥管理**:

```go
// KeyLogStore - SSLKEYLOG 存储
type KeyLogStore struct {
    clientRandom map[string]*KeyMaterial  // CLIENT_RANDOM 映射
    quicSecrets  map[string]*QuicSecrets  // QUIC 密钥
}

// KeyMaterial - TLS 密钥材料
type KeyMaterial struct {
    ClientRandom     []byte
    MasterSecret     []byte
    ClientWriteKey   []byte
    ServerWriteKey   []byte
    ClientWriteIV    []byte
    ServerWriteIV    []byte
}
```

**支持的密码套件**:

| 密码套件 | TLS 版本 | 算法 | 支持状态 |
|---------|---------|------|---------|
| TLS_AES_128_GCM_SHA256 | 1.3 | AES-128-GCM | ✅ |
| TLS_AES_256_GCM_SHA384 | 1.3 | AES-256-GCM | ✅ |
| TLS_CHACHA20_POLY1305_SHA256 | 1.3 | ChaCha20 | ✅ |
| TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 | 1.2 | AES-128-GCM | ✅ |
| TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 | 1.2 | AES-256-GCM | ✅ |

---

### 5. 数据类型层

**位置**: `types/`

**职责**:
- 定义公共接口
- 定义数据结构
- 提供类型转换

**核心类型**:

```go
// 解密数据包
type DecryptedPacket struct {
    Transport  string
    Protocol   string
    Direction  string
    Data       []byte
    Timestamp  time.Time
    Metadata   map[string]interface{}
    SrcIP      string
    SrcPort    uint32
    DstIP      string
    DstPort    uint32
    PID        int64
    PName      string
    DataLength uint32
}

// 连接标识
type ConnectionKey struct {
    SrcIP       net.IP
    SrcPort     uint16
    DstIP       net.IP
    DstPort     uint16
    Protocol    uint8
    Pid         uint32
    ProcessName string
}

// 解密器接口
type Decryptor interface {
    Decrypt(packet gopacket.Packet) error
    GetProtocol() string
    Close() error
}
```

---

## 🔄 数据流

### 完整数据流

```
┌──────────────┐
│ PCAP 文件     │
└──────┬───────┘
       │
       ▼
┌──────────────────┐
│ gopacket 解析     │
│ - Ethernet       │
│ - IP             │
│ - TCP/UDP        │
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│ 连接跟踪          │
│ - 创建连接        │
│ - 查找解密器      │
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│ 传输层解密        │
│ - TLS/QUIC       │
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│ 协议识别          │
│ - HTTP/1.1       │
│ - HTTP/2         │
│ - HTTP/3         │
│ - WebSocket      │
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│ 协议解析          │
│ - 提取元数据      │
│ - 重组消息        │
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│ 输出通道          │
│ DecryptedPacket  │
└──────────────────┘
```

### 连接管理

```go
// 连接跟踪映射
conntrack := make(map[string]types.Decryptor)

// 数据包到达
for packet := range packets {
    // 生成连接键
    connKey := generateConnectionKey(packet)
    
    // 查找或创建解密器
    decryptor, exists := conntrack[connKey]
    if !exists {
        decryptor = factory.CreateDecryptor(connKey)
        conntrack[connKey] = decryptor
    }
    
    // 解密数据包
    err := decryptor.Decrypt(packet)
}
```

---

## 🎯 设计原则

### 1. 单一职责原则 (SRP)

每个模块只负责一个功能：
- `crypto/` 只负责密码学操作
- `transport/` 只负责传输层解密
- `protocol/` 只负责协议解析

### 2. 开闭原则 (OCP)

- 新增协议：实现 `ProtocolParser` 接口并注册
- 新增密码套件：实现解密函数并注册
- 无需修改现有代码

**示例：添加新协议**
```go
// 实现解析器
type MyProtocolParser struct{}

func (p *MyProtocolParser) Parse(data []byte, direction string) ([]*types.DecryptedPacket, error) {
    // 解析逻辑
}

func (p *MyProtocolParser) GetProtocolName() string {
    return "my-protocol"
}

// 注册
func init() {
    RegisterProtocol("my-protocol", &MyProtocolParser{})
}
```

### 3. 依赖倒置原则 (DIP)

- 高层模块不依赖低层模块，都依赖抽象
- 使用接口定义契约：`Decryptor`, `ProtocolParser`

```go
// 接口定义
type Decryptor interface {
    Decrypt(packet gopacket.Packet) error
}

// 高层使用接口
func ProcessPacket(d Decryptor, packet gopacket.Packet) {
    d.Decrypt(packet)
}
```

### 4. 接口隔离原则 (ISP)

- 接口小而专注
- 客户端不依赖不需要的接口

```go
// 好的设计：小接口
type Decryptor interface {
    Decrypt(packet gopacket.Packet) error
}

type ProtocolParser interface {
    Parse(data []byte, direction string) ([]*types.DecryptedPacket, error)
}

// 避免：大而全的接口
// type Processor interface {
//     Decrypt(...) error
//     Parse(...) error
//     Export(...) error
//     ...
// }
```

---

## 🔧 关键技术

### 1. TLS 记录解密

```
TLS Record 结构:
┌────────────────────────┐
│ Type (1 byte)          │ 记录类型
├────────────────────────┤
│ Version (2 bytes)      │ TLS 版本
├────────────────────────┤
│ Length (2 bytes)       │ 数据长度
├────────────────────────┤
│ Encrypted Data         │ 加密数据
│ + Auth Tag             │ + 认证标签
└────────────────────────┘

解密过程:
1. 提取 Nonce = IV ^ SequenceNumber
2. AAD = Type + Version + Length
3. Plaintext = AES_GCM_Decrypt(Key, Nonce, Ciphertext, AAD)
```

### 2. HTTP/2 帧解析

```
HTTP/2 Frame 结构:
┌────────────────────────┐
│ Length (3 bytes)       │ 负载长度
├────────────────────────┤
│ Type (1 byte)          │ 帧类型
├────────────────────────┤
│ Flags (1 byte)         │ 标志位
├────────────────────────┤
│ Stream ID (4 bytes)    │ 流标识符
├────────────────────────┤
│ Frame Payload          │ 帧负载
└────────────────────────┘

帧类型:
- 0x00: DATA
- 0x01: HEADERS
- 0x04: SETTINGS
- 0x08: WINDOW_UPDATE
```

### 3. QUIC 数据包解密

```
QUIC 短头部数据包:
┌────────────────────────┐
│ Header Form (1 bit)    │ 0 = Short
├────────────────────────┤
│ Fixed Bit (1 bit)      │ 必须为 1
├────────────────────────┤
│ Spin Bit (1 bit)       │
├────────────────────────┤
│ Key Phase (1 bit)      │ 密钥阶段
├────────────────────────┤
│ Packet Number (1-4)    │ 数据包号（加密）
├────────────────────────┤
│ Encrypted Payload      │ 加密负载
└────────────────────────┘

解密步骤:
1. 移除头部保护 (Header Protection)
2. 解密 Packet Number
3. 解密 Payload
4. 解析 QUIC 帧
```

---

## 📊 性能优化

### 1. 内存池

```go
// 复用 buffer 减少 GC 压力
var bufferPool = sync.Pool{
    New: func() interface{} {
        return make([]byte, 16384)
    },
}

func decrypt(data []byte) []byte {
    buf := bufferPool.Get().([]byte)
    defer bufferPool.Put(buf)
    // 使用 buf
}
```

### 2. 并发处理

```go
// 使用 goroutine 并发解密
for packet := range packets {
    go func(p gopacket.Packet) {
        decryptor.Decrypt(p)
    }(packet)
}
```

### 3. 流式处理

- 不缓存完整文件
- 边读边处理
- 降低内存占用

---

## 🧪 测试策略

### 单元测试

每个模块独立测试：
```
crypto/          - 密钥解析、解密算法测试
transport/       - TLS/QUIC 解密测试
protocol/        - 协议解析测试
```

### 集成测试

端到端测试：
```go
func TestDecryptPcapFile(t *testing.T) {
    keylog := openTestKeyLog()
    pcap := openTestPcap()
    
    packets := make(chan *types.DecryptedPacket, 100)
    err := DecryptPcapFile(keylog, pcap, packets)
    
    assert.NoError(t, err)
    assert.Greater(t, len(packets), 0)
}
```

---

## 🔗 扩展点

### 添加新协议

1. 实现 `ProtocolParser` 接口
2. 注册到 `protocol_registry.go`
3. 添加协议识别逻辑

### 添加新的密码套件

1. 在 `crypto/decryptor.go` 添加解密函数
2. 在 `crypto/cipher_registry.go` 注册
3. 更新测试用例

### 自定义输出格式

```go
// 自定义处理器
type CustomExporter struct{}

func (e *CustomExporter) Export(packet *types.DecryptedPacket) {
    // 自定义逻辑
}

// 使用
for packet := range packetChan {
    exporter.Export(packet)
}
```

---

## 📖 相关文档

- [API 文档](API.md) - 详细 API 说明
- [开发指南](DEVELOPMENT.md) - 开发环境配置
- [CHANGELOG](../CHANGELOG.md) - 版本历史

---

**维护者**: CFC4N (cfc4n.cs@gmail.com)  
**最后更新**: 2026-01-05

