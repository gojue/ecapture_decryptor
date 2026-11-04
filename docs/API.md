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

#### DecryptPcapngStreamWithOptions / WithOptions

旧的 `DecryptPcapngStream(ctx, input, emit)` 保持默认应用消息输出。
显式 raw 输出及不含明文/密钥的诊断可通过以下入口选择：

```go
options := types.DecryptOptions{
    RawChunks: true,
    OnDiagnostic: func(d types.Diagnostic) {
        // d.ConnectionID, d.Transport, d.Stage, d.Code
    },
}
err := ecapture_decryptor.DecryptPcapngStreamWithOptions(ctx, input, emit, options)
// 文件 API 使用 NewDecryptorConfig().WithOptions(options)，其余配置不变。
```

`input` 必须支持通过 `Close` 中断读取。`emit` 串行执行；其错误停止输入并返回。
诊断回调可能并发执行，必须及时返回，不应回调解密引擎。输出保持背压；调用方
必须消费 packet channel，并让 `emit` 返回，超时和取消不能中断调用方阻塞的回调。

QUIC 的待解密包会由密钥更新唤醒重试，不需要新的 UDP 包或输入 EOF；这同样
适用于末尾才到达的 DSB。尚未获得所需密钥的包继续等待，受下述期限、缓存上限和
关闭时错误检查约束。底层 `crypto.KeyLogStore.Updates()` 返回当前广播通道快照：
添加密钥会关闭该通道。调用方应先订阅、再读取密钥；收到通知后先重新订阅、
再重读，避免错过并发更新。通知可能属于其他连接或重复密钥，不等同于目标密钥已就绪。

`DecryptOptions` 的资源选项对文件和流式入口均有效，非正值采用默认值：

| 选项 | 默认值与行为 |
| --- | --- |
| `KeyWaitTimeout` | 30 秒。TLS 从解密启动起限制握手与密钥获取的总时间；QUIC 从首个缺密钥包入队计时，待解密队列清空后才重置。部分或重复密钥不延期 |
| `IdleTimeout` | 5 分钟。按实际时间回收没有输入包的连接；抓包时间戳不驱动期限。正常 EOF/取消后的排空不计空闲超时 |
| `MaxConnections` | 1024。包含已关闭但尚未结束的解密 goroutine；完成清理后释放额度，超限的新连接被拒绝 |

等待超时报告 `keys/key_wait_timeout`，空闲回收报告 `input/idle_timeout`；并发
上限报告 `input/connection_limit`（每引擎一次）。这些情况会保留终止错误。
连接退出后释放路由、缓存和解析器引用；正常 EOF 仍先处理已缓冲数据和末尾 DSB。

固定缓存边界：TLS 每方向输入 8 MiB，server-first 和旧 stdout 响应队列各
8 MiB / 65,536 块；QUIC 输入及待密钥队列各 32 MiB / 65,536 包，每连接最多
1,024 个方向化 stream 状态（含完成标记）。TCP 每方向乱序重组保持 4 MiB，
QUIC 每个 STREAM/CRYPTO assembler 保持 16 MiB，两者各最多 65,536 个乱序片段。
超限报告 `resource_limit` 并终止该连接。这些是各组件上限，不是整个引擎的统一
内存预算；现有应用 parser 上限继续有效。

keylog 的 `Write` / `LoadFromReader` 导入每行最多 4096 字节（LF 前）、最多
16,384 个 client random、16 MiB secret 字节；超限返回不含内容的
`crypto.ErrKeyLogResourceLimit`，已导入密钥保留，未完成行释放。同 key 更新按
字节增量计费。兼容入口 `AddSecret` 信任调用方管理内存，不应用导入上限。

raw 事件复用 `DecryptedPacket`：`Protocol` 为 `tls` 或 `quic`，`Data` 是
已认证的原始字节；`Direction=request/response` 分别表示客户端到服务端、
服务端到客户端，不代表应用层请求/响应。`Metadata` 包含：

| 字段 | 类型和含义 |
| --- | --- |
| `kind` | `stream_chunk`，或不携带数据的 `stream_end` / QUIC `stream_reset` |
| `offset` | `uint64`，TLS 按连接/方向，QUIC 按连接/方向/stream 的字节偏移 |
| `end` | `bool`，QUIC 表示连续数据到达 FIN 或收到 RESET_STREAM；TLS 表示捕获输入结束 |
| `stream_id` | QUIC 的 `uint64` stream ID；TLS 不设置 |
| `error_code` | 仅 `stream_reset`，`uint64` 应用错误码；此时 `offset` 是最终大小，不保证此前所有字节都已捕获 |

chunk 边界不是应用消息边界，raw 与应用解析互斥，不依赖 ALPN 或自动识别。
TLS 终止错误时保留已认证字节并返回错误，不发送正常结束标记；捕获结束本身
不证明应用消息完整。QUIC 只输出连续 STREAM 字节，已知 offset 缺口在关闭时报错。
RESET_STREAM 释放该方向的重组和解析缓存，保留有界终止标记以去重；它不伪装为完整 HTTP 消息。
0-RTT RESET 使用下述接受/拒绝规则和独立 early 空间，raw reset 同样带阶段/接受状态。
STOP_SENDING 只表示请求对端停止，不能替代 RESET 或 FIN。
不支持 DATAGRAM 输出、TLS KeyUpdate 或 STARTTLS；QUIC Key Update、
CID/Retry/VN 和 0-RTT 支持范围见下节。现有 QUIC 16 MiB stream offset 上限仍适用。

`Diagnostic` 仅含连接标识、传输、阶段和固定原因码，不含底层错误字符串。
典型原因包括 `waiting_secret`、`missing_secret`、`missing_client_hello`、
`unsupported_version`、`unsupported_cipher`、`authentication_failed`、
`unsupported_protocol`、`parse_failed`、`parse_timeout`、`truncated_record`、`incomplete_stream`
和 `resource_limit`。`waiting_secret` 表示暂时等待，并非最终失败；只有 application
secret 时，无法区分仅含加密握手的记录与缺少正确密钥的应用记录，终止时报告
`no_authenticated_application_data`，不直接判定认证失败。
诊断用于解释输出缺失，不保证每个包一条，也不替代函数返回的终止错误。

---

#### QUIC Key Update

QUIC v1/v2 的两个方向独立跟踪 application 密钥代次，支持 phase `0→1→0` 及后续更新。
只需提供匹配的 `CLIENT_TRAFFIC_SECRET_0` / `SERVER_TRAFFIC_SECRET_0`；无需持续导入
后续 secret。v1 使用 `quic ku`，v2 使用 `quicv2 ku`；header protection key 不变，
包号不重置。只有 AEAD 认证成功且 phase/包号满足代次顺序时才推进状态或输出。

每方向只尝试当前代、上一代和下一代候选，最多三代；尚未确认套件时最多有
AES-128 / ChaCha20 两组候选。下一代派生结果会缓存，坏包不导致重复派生。
上一代只接受比当前代已认证最小包号更早的包；更旧代在下一次成功换代时淘汰，
全部状态在连接退出时释放。该保留策略按代次数量限制，不模拟端点的 ACK/PTO。
待密钥队列按方向和加密级别保留输入顺序，避免密钥在重试途中到达时跳过旧代包。

不会无限追算漏掉的代次；捕获缺失整个中间代、已淘汰旧代、错误 secret、篡改
phase 或密文均可能导致 `decrypt/authentication_failed`，并保留终止错误。
此诊断不声称能区分丢包、过旧包和坏密钥。raw/messages、文件和非 seekable 流式
入口使用同一状态机，既有背压、缓存、等待期限和错误返回契约不变。

真实 loopback 抓包验证 v1/v2 × AES-128-GCM 的双向多次更新；AES-256-GCM 和
ChaCha20-Poly1305 由独立固定派生向量及状态测试覆盖，未宣称真实套件全矩阵通过。
生成器修正、实际换代证据及命令见 [HTTP/3 fixture 说明](../test/fixtures/http3_capture/README.md#key-update-fixtures)。
TLS 1.3 的 KeyUpdate 属于另一个协议状态机，本次没有新增其支持。

#### QUIC 连接身份、Retry/VN 与 0-RTT

非零 CID 索引将双向流量、NEW/RETIRE_CONNECTION_ID、CID 轮换与地址迁移归入同一
`ConnectionID` / `Generation`；输出地址保留初始连接地址。同一 tuple 的不同连接按
Initial/CID 区分，不凭地址将未知 CID 归入已有连接。零长度 CID 仅支持唯一的原 tuple，
不能用于识别迁移；碰撞、多个可能匹配的 CID/长度或零 CID tuple 报
`input/ambiguous_connection_id`，不输出该包。退役 CID 从索引删除，非原始 tuple 别名
同时清理；无法关联的迟到旧 CID 包也遵循未知 CID 边界。没有任何可关联起始连接时，
沿用 `handshake/missing_connection_start` 诊断。

每方向最多 64 个带 sequence 的 CID/退役标记；路由每方向最多 66 个 ID（含原始/
Retry 临时 ID），每连接最多 8 个 tuple 别名。未知 CID 全引擎共用 32 MiB / 65,536 包
等待队列，认证后的 CID 信息可在没有下一包或 EOF 时释放待路由包。以
`KeyWaitTimeout` 为期限，达到后由巡检清理（检查周期不大于该值的一半），EOF 也清空；未解决时报告
`input/unknown_connection_id` 并保留终止错误。CID/别名在取消、超时和 worker 退出时
释放，正在退出的 worker 仍占连接额度。超限不扩容或猜测关联。

v1/v2 Retry 验证格式、token 和 RFC 完整性 tag；最多处理一次 Retry，只在后续新
DCID Initial 认证通过且 token/客户端 SCID 匹配后切换 Initial 密钥与 CRYPTO 重组
epoch。Retry 不重置包号；仅保留一组前 epoch Initial 密钥，用于忽略可认证的迟到旧包。
VN 最多观察 16 个非零版本，拒绝异常列表；只有后续受支持版本的 Initial 认证成功
才选择版本。已经观察到有效服务端 Initial、Handshake 或 1-RTT 的连接不再接受 VN
改变版本。Retry 完整性使用公开固定密钥，VN 没有密码学认证；这两者都不证明服务端
身份，也不替代 TLS 的证书/握手验证。固定诊断包括 `handshake/invalid_retry`、
`invalid_version_negotiation`、`invalid_negotiation` 和 `decrypt/version_change`。

0-RTT 使用 `CLIENT_EARLY_TRAFFIC_SECRET`，与 1-RTT 共享 application 包号空间。
已认证的 early STREAM 字节先缓冲，只有解密后的服务端 EncryptedExtensions 中的
`early_data` 扩展才能确认接受；扩展缺失表示拒绝。只解出 early 字节不代表被服务端接受。

- **messages**：接受后合入正常 STREAM 重组，按 offset 去重；拒绝时丢弃 early 字节，
  后续 1-RTT 重传仅输出一次业务消息。已确认拒绝时，缺 early secret 不阻塞业务重传。
- **raw**：接受后同样合入正常 STREAM；拒绝的已认证字节仍输出，但使用独立的 early
  offset 空间。early chunk 增加 `encryption_level="0rtt"` 和
  `early_data="accepted"|"rejected"|"unknown"`；观察过 early STREAM 后的正常 chunk
  标记 `encryption_level="1rtt"`。接受的 0/1-RTT 共用 offset/FIN 与去重状态；拒绝或
  unknown 的 early 空间与正常 1-RTT 空间分别计算 offset/FIN，消费者不能将两者当作
  两次业务请求。未出现 early STREAM 的连接保持原 metadata 形状。
- **未知**：等待接受信息同样受 `KeyWaitTimeout` 限制，每连接最多 32 MiB / 65,536 个
  early frame。期限或 EOF 到达仍未知时，raw 输出已认证的连续字节并标记 `unknown`，
  messages 丢弃未确认 early 字节；两者报告 `handshake/early_data_unknown` 并返回错误。
  缺 secret 的密文不产生 raw 明文，沿用 `missing_secret` / `key_wait_timeout`。

接受/拒绝诊断为 `handshake/early_data_accepted` / `early_data_rejected`，没有明文或密钥。
raw 的 rejected/unknown early assembler 与正常 STREAM 分开，各受现有 stream 数量、
16 MiB offset 与片段上限限制。流式 API 仍按既有背压契约交付，不启动无限输出队列。

独立真实夹具与固定向量覆盖 v1/v2 × AES-128-GCM/AES-256-GCM/ChaCha20-Poly1305。
实际 18 条连接产生 24 次请求/响应，其中 6 条经过迁移，6 条接受 early data，6 条拒绝后
以 1-RTT 重传；文件、内嵌 DSB、末尾 DSB 和 raw/messages 回放相互核对。
Retry 与 0-RTT 使用独立连接；未宣称真实覆盖二者组合、draft-29 或每种套件的 Key Update。


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
    "headers": http.Header{...},  // 普通头部，不含伪头和 trailers
}
```

**Response 元数据：**
```go
{
    "stream_id": 0,               // QUIC 流 ID
    "status": 200,                // int，:status 伪头
    "headers": http.Header{...},  // 普通头部，不含伪头和 trailers
}
```

连接内的 client/server QPACK 动态表相互独立，控制流、encoder/decoder 流、请求流与 push 流分别处理。支持静态表、字面量、Huffman、动态插入/复制/淘汰及相对和 post-base 引用。HEADERS 等待 encoder 指令时保留冻结的 Required Insert Count；插入到达后立即恢复，不等下一业务包或 EOF。对端 SETTINGS 迟到时按原顺序有界重放待处理数据。SDK 被动观察 decoder feedback 的指令格式，不发送 ACK、不驱动对端，也不依据抓包到达顺序验证 ACK 所对应的发送端引用生命周期。

- 完整请求、最终响应在该方向 FIN 时输出。`Data` 保持 HTTP/3 文本头 + `\r\n\r\n` + 精确 body 字节；`headers` 只包含普通初始头部。
- 1xx（不含非法的 101）立即以 `kind="informational"`、`status` 为 `int` 输出，保留原 `stream_id`；不会占用最终响应。`trailers` 为单独的 `http.Header`，只在存在非空 trailers 时设置，不合并进 `headers` 或 `Data`。
- push 响应使用 `kind="push_response"`、实际 push `stream_id`、`push_id`、`parent_stream_id`；`method/path/scheme/authority/promise_headers` 描述关联 PUSH_PROMISE 请求。push 字节可先于 promise/授权到达，但关联完整后才交付。push 的 1xx 仍为 `informational` 并携带 push 标识。相同 promise 去重，取消/RESET 丢弃未完成响应。
- CLI HAR 配对只使用普通请求和最终响应；信息响应与 push 不冒充原请求的最终响应。JSON/SDK 消费者可以按上述 `kind` 区分；`Data` 的 JSON 排除规则不变。
- SETTINGS 必须是控制流首帧，拒绝重复控制/QPACK 流、重复/保留 SETTINGS、非法帧位置及关键流关闭。未知合法帧/单向流跳过；不按其声明长度分配内存。

上限：每方向实际动态表 64 KiB、每个解码字段节 64 KiB（按 name + value + 32 计）/1024 字段；每方向最多 64 条阻塞流，同时受对端 SETTINGS 限制。解析器最多保留 1024 个流标记、128 个 push；每个未关联 push 最多 16 个信息响应；待 SETTINGS 重放每方向最多 4096 个片段。连接内消息/流缓冲和待重放字节共 32 MiB，单消息/底层 QUIC stream offset 仍为 16 MiB。超限返回终止错误并报告 `protocol/resource_limit`，不跳过失败断言或扩大缓存。

QPACK、SETTINGS 和消息顺序错误报告 `protocol/parse_failed`，不归为密码学认证失败。阻塞压缩/未关联 push 使用实际时间的 `KeyWaitTimeout`，逾期报告 `protocol/parse_timeout`；EOF 尚有不完整状态也返回错误。RESET、取消和关闭释放等待数据，正常结束仅保留有界去重/关联信息；输出继续遵守串行背压。缺失必要 encoder 历史或 SETTINGS 的片段捕获不能保证动态解码。扩展 CONNECT、长流增量输出以及 DATAGRAM 不在此支持范围。

独立 `http3_dynamic_aioquic` 夹具及 [复现步骤](../test/fixtures/http3_capture/README.md#dynamic-qpack-and-message-state-fixture) 覆盖 QUIC v1、两条连接、双向动态表、延迟/拆分 encoder、103→200→trailers、push/reset；v2 的动态 HTTP/3 组合和 0-RTT RESET 尚无真实夹具，后者仅有状态回归。

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
| HTTP/3 | `http/3` | ✅ 有界消息解析 | QUIC + 动态 QPACK；边界见上节 |
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

