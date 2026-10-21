# API Reference - API 参考文档

本文档详细说明 ecapture_decryptor 的所有公开 API。

## 📦 包结构

```
github.com/gojue/ecapture_decryptor
├── /                          # 主包 - 公开API
├── /types                     # 类型定义
├── /crypto                    # 加密/解密模块（内部）
├── /transport                 # 传输层解密（内部）
└── /protocol                  # 协议解析（内部）
```

---

## 🔧 核心 API

### 解密函数

#### DecryptPcapFile

解密 PCAP/PCAPNG 文件中的流量。

```go
func DecryptPcapFile(
    keylogReader io.Reader,
    pcapFileHandle io.Reader,
    packetChan chan *types.DecryptedPacket,
) error
```

**参数：**
- `keylogReader`: 可选的外部 SSLKEYLOG 文件读取器；传入 `nil` 时使用 pcapng 内嵌 DSB。提供读取器时也会加载 DSB。
- `pcapFileHandle`: PCAP/PCAPNG 文件的读取器
- `packetChan`: 输出通道，接收解密后的数据包

**返回：**
- `error`: 错误信息，成功返回 nil

**示例：**
```go
keylog, _ := os.Open("sslkey.log")
pcap, _ := os.Open("traffic.pcap")
defer keylog.Close()
defer pcap.Close()

packetChan := make(chan *types.DecryptedPacket, 100)

go func() {
    for packet := range packetChan {
        fmt.Printf("Protocol: %s, Direction: %s\n", 
            packet.Protocol, packet.Direction)
    }
}()

err := ecapture_decryptor.DecryptPcapFile(keylog, pcap, packetChan)
if err != nil {
    log.Fatal(err)
}
close(packetChan)
```

---

#### DecryptLiveTraffic

解密实时流量（从网卡或实时 PCAP 流）。

```go
func DecryptLiveTraffic(
    keylogReader io.Reader,
    pcapHandle io.Reader,
    packetChan chan *types.DecryptedPacket,
) error
```

**参数：**
- `keylogReader`: SSLKEYLOG 文件的读取器
- `pcapHandle`: 实时 PCAP 流的读取器
- `packetChan`: 输出通道，接收解密后的数据包

**返回：**
- `error`: 错误信息

**使用场景：**
- 实时抓包解密
- 网络流量监控
- 实时协议分析

---

#### DecryptWithConfig

使用高级配置进行解密。

```go
func DecryptWithConfig(config *DecryptorConfig) error
```

**参数：**
- `config`: 解密器配置对象

**返回：**
- `error`: 错误信息

**示例：**
```go
config := ecapture_decryptor.NewDecryptorConfig().
    WithSSLKeyLog(keylogReader).
    WithPcapReader(pcapReader).
    WithPacketChan(packetChan).
    WithLogger(customLogger)

err := ecapture_decryptor.DecryptWithConfig(config)
```

---

### 配置构建器

#### DecryptorConfig

解密器配置对象，使用 Builder 模式构建。

**方法：**

##### NewDecryptorConfig

创建新的配置对象。

```go
func NewDecryptorConfig() *DecryptorConfig
```

##### WithSSLKeyLog

设置 SSLKEYLOG 读取器。

```go
func (c *DecryptorConfig) WithSSLKeyLog(reader io.Reader) *DecryptorConfig
```

##### WithPcapReader

设置 PCAP 数据源。

```go
func (c *DecryptorConfig) WithPcapReader(reader io.Reader) *DecryptorConfig
```

##### WithPacketChan

设置解密包输出通道。

```go
func (c *DecryptorConfig) WithPacketChan(ch chan *types.DecryptedPacket) *DecryptorConfig
```

##### WithLogger

设置自定义日志记录器。

```go
func (c *DecryptorConfig) WithLogger(logger *log.Logger) *DecryptorConfig
```

**完整示例：**
```go
logger := log.New(os.Stdout, "[Decryptor] ", log.LstdFlags)
config := ecapture_decryptor.NewDecryptorConfig().
    WithSSLKeyLog(keylogFile).
    WithPcapReader(pcapFile).
    WithPacketChan(packetChan).
    WithLogger(logger)

err := ecapture_decryptor.DecryptWithConfig(config)
```

---

## 📊 数据类型

### DecryptedPacket

解密后的数据包结构。

```go
type DecryptedPacket struct {
    // 传输层协议 ("tcp" 或 "udp")
    Transport string `json:"transport"`
    
    // 应用层协议 ("http/1.1", "http/2", "http/3", "websocket")
    Protocol string `json:"protocol"`
    
    // 方向 ("request" 或 "response")
    Direction string `json:"direction"`
    
    // 解密后的应用层数据
    Data []byte `json:"-"`
    
    // 数据包捕获时间
    Timestamp time.Time `json:"timestamp"`
    
    // 协议特定元数据
    Metadata map[string]interface{} `json:"metadata"`
    
    // 源 IP 地址
    SrcIP string `json:"srcIP"`
    
    // 源端口
    SrcPort uint32 `json:"srcPort"`
    
    // 目标 IP 地址
    DstIP string `json:"dstIP"`
    
    // 目标端口
    DstPort uint32 `json:"dstPort"`
    
    // 进程 ID
    PID int64 `json:"PID"`
    
    // 进程名称
    PName string `json:"PName"`
    
    // 数据长度
    DataLength uint32 `json:"dataLength"`
}
```

#### 方法

##### NewDecryptedPacket

创建新的解密数据包（内部使用）。

```go
func NewDecryptedPacket(
    tProtocol, protocol, direction string,
    data []byte,
    timestamp time.Time,
    ci ConnectionKey,
) *DecryptedPacket
```

##### WithMetadata

添加元数据。

```go
func (p *DecryptedPacket) WithMetadata(key string, value interface{}) *DecryptedPacket
```

##### IsRequest

判断是否为请求包。

```go
func (p *DecryptedPacket) IsRequest() bool
```

##### IsResponse

判断是否为响应包。

```go
func (p *DecryptedPacket) IsResponse() bool
```

##### Meta

获取 JSON 格式的元数据。

```go
func (p *DecryptedPacket) Meta() string
```

**使用示例：**
```go
for packet := range packetChan {
    fmt.Printf("From: %s:%d -> %s:%d\n", 
        packet.SrcIP, packet.SrcPort,
        packet.DstIP, packet.DstPort)
    
    fmt.Printf("Protocol: %s\n", packet.Protocol)
    fmt.Printf("Direction: %s\n", packet.Direction)
    fmt.Printf("Data Length: %d\n", packet.DataLength)
    
    if packet.IsRequest() {
        fmt.Println("This is a request packet")
    }
    
    // 访问协议特定元数据
    if method, ok := packet.Metadata["method"]; ok {
        fmt.Printf("HTTP Method: %s\n", method)
    }
}
```

---

## 🔍 元数据格式

不同协议的元数据格式不同。

### HTTP/1.1

**Request 元数据：**
```go
{
    "method": "GET",              // HTTP 方法
    "url": "/path/to/resource",   // 请求 URL
    "host": "example.com",        // Host 头
    "headers": http.Header{...},  // 所有请求头
}
```

**Response 元数据：**
```go
{
    "status": 200,                // HTTP 状态码
    "headers": http.Header{...},  // 所有响应头
}
```

### HTTP/2

**Request 元数据：**
```go
{
    "stream_id": 1,               // HTTP/2 流 ID
    "method": "GET",              // HTTP 方法
    "path": "/path",              // 请求路径
    "authority": "example.com",   // :authority 伪头
    "scheme": "https",            // :scheme 伪头
    "headers": http.Header{...},  // 所有头部
}
```

**Response 元数据：**
```go
{
    "stream_id": 1,               // HTTP/2 流 ID
    "status": "200",              // :status 伪头
    "headers": http.Header{...},  // 所有头部
}
```

### HTTP/3

**Request 元数据：**
```go
{
    "stream_id": 0,               // QUIC 流 ID
    "method": "GET",              // HTTP 方法
    "path": "/path",              // 请求路径
    "authority": "example.com",   // :authority 伪头
    "scheme": "https",            // :scheme 伪头
    "headers": http.Header{...},  // 所有头部（QPACK 解码后）
}
```

**Response 元数据：**
```go
{
    "stream_id": 0,               // QUIC 流 ID
    "status": "200",              // :status 伪头
    "headers": http.Header{...},  // 所有头部（QPACK 解码后）
}
```

### WebSocket

**握手元数据：**
```go
{
    "upgrade": true,              // WebSocket 升级
    "headers": http.Header{...},  // 握手头部
}
```

**消息元数据：**
```go
{
    "opcode": 1,                  // WebSocket 操作码 (1=text, 2=binary)
    "fin": true,                  // 是否为最后一个分片
    "masked": true,               // 是否掩码
}
```

---

## 🔐 支持的协议

| 协议 | Protocol 字段 | 支持程度 | 说明 |
|------|---------------|----------|------|
| HTTP/1.1 | `http/1.1` | ✅ 完整 | 包括 chunked 编码 |
| HTTP/2 | `http/2` | ✅ 完整 | 帧解析、流重组 |
| HTTP/3 | `http/3` | ✅ 完整 | QUIC + QPACK |
| WebSocket | `websocket` | ✅ 完整 | 包括分片消息 |

---

## 🚀 高级用法

### 自定义日志

```go
logger := log.New(os.Stdout, "[DEBUG] ", log.LstdFlags|log.Lshortfile)

config := ecapture_decryptor.NewDecryptorConfig().
    WithSSLKeyLog(keylogReader).
    WithPcapReader(pcapReader).
    WithPacketChan(packetChan).
    WithLogger(logger)

err := ecapture_decryptor.DecryptWithConfig(config)
```

### 批量处理

```go
files := []string{"capture1.pcap", "capture2.pcap", "capture3.pcap"}
keylog, _ := os.Open("sslkey.log")

packetChan := make(chan *types.DecryptedPacket, 1000)

// 处理线程
go func() {
    for packet := range packetChan {
        processPacket(packet)
    }
}()

// 批量解密
for _, file := range files {
    pcap, _ := os.Open(file)
    err := ecapture_decryptor.DecryptPcapFile(keylog, pcap, packetChan)
    if err != nil {
        log.Printf("Error decrypting %s: %v", file, err)
    }
    pcap.Close()
}

close(packetChan)
```

### 过滤特定协议

```go
packetChan := make(chan *types.DecryptedPacket, 100)

go func() {
    for packet := range packetChan {
        // 只处理 HTTP/2 请求
        if packet.Protocol == "http/2" && packet.IsRequest() {
            processHTTP2Request(packet)
        }
    }
}()

err := ecapture_decryptor.DecryptPcapFile(keylog, pcap, packetChan)
```

---

## ⚠️ 注意事项

### 并发安全

- ✅ `DecryptPcapFile()` 是并发安全的
- ✅ `DecryptLiveTraffic()` 是并发安全的
- ⚠️ 多个 goroutine 可以同时读取 `packetChan`，但应该只有一个写入者

### 资源管理

```go
// 正确的资源管理
keylog, err := os.Open("sslkey.log")
if err != nil {
    return err
}
defer keylog.Close()

pcap, err := os.Open("traffic.pcap")
if err != nil {
    return err
}
defer pcap.Close()

packetChan := make(chan *types.DecryptedPacket, 100)
defer close(packetChan)

// ... 使用 API
```

### Channel 缓冲

建议设置适当的 channel 缓冲大小：

```go
// 小文件：较小的缓冲
packetChan := make(chan *types.DecryptedPacket, 100)

// 大文件或实时流：较大的缓冲
packetChan := make(chan *types.DecryptedPacket, 1000)
```

---

## 📝 错误处理

API 返回的常见错误：

| 错误 | 说明 | 解决方法 |
|------|------|----------|
| `invalid pcap format` | PCAP 文件格式错误 | 检查文件是否为有效的 PCAP/PCAPNG |
| `no valid keys found` | SSLKEYLOG 文件无效或为空 | 检查 keylog 文件格式 |
| `unsupported protocol` | 不支持的协议 | 当前仅支持 TLS/QUIC |
| `channel closed` | 输出通道已关闭 | 确保通道在使用期间保持打开 |

**错误处理示例：**
```go
err := ecapture_decryptor.DecryptPcapFile(keylog, pcap, packetChan)
if err != nil {
    switch {
    case strings.Contains(err.Error(), "invalid pcap"):
        log.Fatal("Invalid PCAP file format")
    case strings.Contains(err.Error(), "no valid keys"):
        log.Fatal("SSLKEYLOG file is empty or invalid")
    default:
        log.Fatalf("Decryption error: %v", err)
    }
}
```

---

## 🔗 相关文档

- [架构文档](ARCHITECTURE.md) - 系统架构设计
- [CHANGELOG](../CHANGELOG.md) - 版本历史
- [示例代码](../examples/) - 完整示例

---

**维护者**: CFC4N (cfc4n.cs@gmail.com)  
**最后更新**: 2026-01-05

