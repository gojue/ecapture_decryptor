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

解密调用方提供的实时 PCAP/PCAPNG 数据流；函数本身不打开网卡。

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
显式 raw 输出、[DNS/MQTT/Redis 解析](#applicationprotocol)及不含明文/密钥的诊断可通过以下入口选择：

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
QUIC 每个 STREAM/CRYPTO assembler 的乱序载荷最多 16 MiB、65,536 个片段。连接的 STREAM 乱序缓存合计最多 32 MiB、65,536 个片段，包括独立的 early 空间。
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
| `offset` | `uint64`，TLS 按连接/方向（TLSUpgrade 还按 tls_depth），QUIC 按连接/方向/stream 的字节偏移 |
| `end` | `bool`，QUIC 表示连续数据到达 FIN 或收到 RESET_STREAM；TLS 表示捕获输入结束 |
| `stream_id` | QUIC 的 `uint64` stream ID；TLS 不设置 |
| `error_code` | 仅 `stream_reset`，`uint64` 应用错误码；此时 `offset` 是最终大小，不保证此前所有字节都已捕获 |

chunk 边界不是应用消息边界，同一层的 raw 与应用解析互斥，不依赖 ALPN 或自动识别；TLSUpgrade 可同时交付外层 raw 与内层应用消息。
TLS 终止错误时保留已认证字节并返回错误，不发送正常结束标记；捕获结束本身
不证明应用消息完整。QUIC STREAM 只输出连续字节，已知 offset 缺口在关闭时报错；DATAGRAM 不参与该重组。
RESET_STREAM 释放该方向的重组和解析缓存，保留有界终止标记以去重；它不伪装为完整 HTTP 消息。
0-RTT RESET 使用下述接受/拒绝规则和独立 early 空间，raw reset 同样带阶段/接受状态。已捕获的 early 密文或接受状态尚待确认时，后续客户端 1-RTT STREAM/RESET 复用有界 early 队列等待，并保持这些帧的顺序，避免 RESET 丢失 early 前缀或被后到 FIN 越过。正常后缀保留 1-RTT 阶段；拒绝/未知 early 与正常 1-RTT STREAM/RESET 分别处理。
STOP_SENDING 只表示请求对端停止，不能替代 RESET 或 FIN。
QUIC DATAGRAM 与 DTLS 数据报见 [数据报输出](#数据报输出)；TLS KeyUpdate 及 TLS 阶段边界见 [TLS 版本与状态](#tls-版本与状态)，STARTTLS/CONNECT 见 [TLSUpgrade](#tlsupgrade)。QUIC Key Update、
CID/Retry/VN 和 0-RTT 支持范围见下节。raw / HTTP 增量模式支持 QUIC 62 位 STREAM offset，完整消息和 CRYPTO 保留 16 MiB 的累计限制。

`Diagnostic` 仅含连接标识、传输、阶段和固定原因码，不含底层错误字符串。
典型原因包括 `waiting_secret`、`missing_secret`、`missing_client_hello`、
`unsupported_version`、`unsupported_cipher`、`authentication_failed`、
`unsupported_protocol`、`parse_failed`、`parse_timeout`、`truncated_record`、`incomplete_stream`
和 `resource_limit`。`waiting_secret` 表示暂时等待，并非最终失败；只有 application
secret 时，无法区分仅含加密握手的记录与缺少正确密钥的应用记录，终止时报告
`no_authenticated_application_data`，不直接判定认证失败。
诊断用于解释输出缺失，不保证每个包一条，也不替代函数返回的终止错误。

---

#### 数据报输出

QUIC `types.DecryptOptions{RawChunks: true}` 在既有 STREAM 事件之外输出 [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221.html) DATAGRAM：`Protocol="quic"`、`Metadata["kind"]="datagram"`，每个已认证 frame 一条输出，`Data` 保留完整消息边界及空载荷。支持 `0x30` 隐式长度和 `0x31` 显式长度；不设置 `stream_id`、`offset` 或 `end`，也不生成数据报结束事件。`encryption_level` 始终是 `0rtt` 或 `1rtt`；0-RTT 另带 `early_data=accepted/rejected/unknown`，拒绝/未知的已认证字节仍可通过 raw 保留，不表示对端接受了它。

同方向的 0/1-RTT 共享 packet-number 去重，只有认证成功的 packet 才登记；重复捕获不重复输出，不同 packet 或同 packet 中内容相同的多个 DATAGRAM 仍分别输出。已见 packet number 保存为合并区间，每方向最多 65,536 个离散区间，超限明确返回 `resource_limit`，不靠 payload 去重。未决 early 及其后待释放的客户端 DATAGRAM 复用有界 early 队列（32 MiB/65,536 frames）与密钥期限；普通 1-RTT 消息不等 STREAM 缺口。输出使用既有串行回调/背压，不创建无限消息队列。

默认应用模式继续忽略底层 DATAGRAM；未知的已认证 ALPN 仍要求显式 raw。此输出不实现重传、可靠交付、应用排序、HTTP DATAGRAM context、WebTransport session 或 MASQUE capsule，也不完整校验对端 DATAGRAM transport parameter 的协商。独立 aioquic 真实夹具覆盖 QUIC v1/v2、AES-128-GCM、空/二进制/同内容消息、多 frame、accepted/rejected 0-RTT；其他边界由状态测试覆盖，不能据此宣称 WebTransport/MASQUE 已支持。

DTLS 采用独立显式入口选项 `types.DecryptOptions{UDPProtocol: "dtls"}`。空值或 `"quic"` 保留 UDP→QUIC，TCP 仍走 TLS；不按端口猜测，选项作用于本次调用的全部 UDP 连接。DTLS 选项与 `ApplicationProtocol`、`TLSUpgrade`、`HTTPEvents`、非零 `MaxDecodedBodyBytes` 互斥；`RawChunks` 可用但不改变 DTLS 输出。文件 API 必须并发消费 packet channel，流式 API 继续接受外部 keylog/内嵌或迟到 DSB、取消及回调错误排空。CLI/C 示例未增加此选项。

首批仅支持 [DTLS 1.2](https://www.rfc-editor.org/rfc/rfc6347.html) 的 `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` (`0xc02f`) / `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` (`0xc030`)，需要包含 ClientHello/ServerHello 的双向捕获及匹配的 `CLIENT_RANDOM <client random> <48-byte master secret>`。复用 TLS PRF/key block，按 [AES-GCM record](https://www.rfc-editor.org/rfc/rfc5288.html) 的 epoch、48 位序号、显式 nonce 和 AAD 认证。允许初始 epoch 0 的兼容 `0xfeff` record header，但实际 Hello 版本必须是 `0xfefd`；加密输出限定 epoch 1。

每个认证成功的 application record 输出一条 `Protocol="dtls"`、`Transport="udp"`、`kind="datagram"`，含 `epoch` (`uint16`) 与 `sequence` (`uint64`)；无 stream offset、FIN 或应用解析。方向由 ClientHello 识别，时间戳来自该 record 的捕获包。每方向保留 128-record replay window，认证失败不推进窗口，重复或落在窗口之前的 record 不输出；窗口内乱序可即时输出，不排序、等待缺口或补包。坏认证保留固定诊断/最终错误，其他可认证记录仍可输出。

连接 ID 固定为首次捕获的 UDP tuple/代次，cookie retry 保持同一连接；同 tuple 的新 random/重协商不自动视为新连接，明确报不支持，直至 EOF/空闲回收。DTLS 输入队列和迟到密钥队列各为 4 MiB/4,096 项，worker 取出的当前批次也最多 4 MiB；单 UDP 最多 65,535 字节，明文 record 最多 16 KiB。握手按方向/epoch/message_seq 重组，单消息 256 KiB，未完成握手与已完成 Hello 留存载荷合计 1 MiB（未完成消息另有等长接收位图），最多 64 个消息身份含完成标记；冲突片段、截断和超限报错。握手/密钥等待使用首次启动的实际时间期限，部分消息或重复密钥不延期；正常 EOF 排空，缺密钥/未完成握手仍返回错误，关闭释放缓存和连接额度。

独立 OpenSSL 真实 DTLS 夹具覆盖两套件、HelloVerifyRequest、MTU 512 的握手分片和双向重复二进制载荷；空 record、乱序、重传、坏认证和资源边界使用确定性状态测试。此最小实现不支持 DTLS 1.0/1.3、CID、epoch 更新/重协商，也不提供完整证书身份或 Finished transcript 验证。DTLS 外层解密不等于 CoAP、SCTP/DataChannel、SRTP 或 WebRTC 已支持；这些应用与 WebTransport/MASQUE 均是后续独立子项。

#### HTTP 增量事件

Go 文件和流式入口均接受 `types.DecryptOptions{HTTPEvents: true}`。文件入口需要并发消费 packet channel。零值选项输出完整应用消息。HTTPEvents 和 RawChunks 互斥，选项冲突在读取输入前返回错误。CLI/HAR 和 C 示例使用默认完整消息模式。

```go
err := ecapture_decryptor.DecryptPcapngStreamWithOptions(ctx, input,
    func(p *types.DecryptedPacket) error {
        if p.Metadata["kind"] == "sse" {
            fmt.Printf("%s %s\n", p.Metadata["event"], p.Data)
        }
        return nil
    }, types.DecryptOptions{HTTPEvents: true})
```

`Protocol` 记录 HTTP 版本。用 `ConnectionID()`、`stream_id`（`uint64`）和 `Direction` 定位事件。HTTP/1 按请求头的到达顺序从 1 编号，配对的响应使用同一编号。HTTP/2 和 HTTP/3 使用线上 stream ID。每条消息的每个方向独立从 offset 0 开始，多个流和连接允许交错。捕获时间戳不参与排序。

| `Metadata["kind"]` | 交付内容和顺序 |
| --- | --- |
| `headers` | `headers` 是独立的 `http.Header`。请求有 `method` 和 `url`（HTTP/1）或 `path`（HTTP/2、3），响应有整数 `status`。1xx 附 `informational=true`，随后仍可收到最终 headers。HTTP/3 push 的 headers 携带 `push_id`、`parent_stream_id` 和 promise 元数据。 |
| `body_chunk` | `Data` 为已去除 HTTP framing 的正文，最多 32 KiB。`offset` 是本片段首字节的正文位置。只拼接这一类事件即可重建正文。 |
| `sse` | 对 `text/event-stream` 响应，空行结束一条事件时额外交付。`Data` 是多行 data 字段以换行拼接后的 UTF-8 数据。`event` 默认是 `message`，`last_event_id` 保留最近的 id，已观察到有效 retry 时带 `retry_ms`（`uint64`）。`offset` 指向触发派发的行结束符之后。EOF 时仅有半条 SSE 记录则不派发。 |
| `trailers` | 独立的 `trailers` 字段，offset 为已交付正文长度。 |
| `end` | 当前方向正常结束，offset 为正文总长度。 |
| `reset` | 已开始的方向被取消，offset 为已经交付的正文长度。HTTP/2 RST_STREAM 结束该 stream 两个仍打开的方向，HTTP/3 RESET_STREAM 结束发送方向，两者携带 `error_code`。CANCEL_PUSH 和 TCP RST 也可终止已开始的消息。 |
| `partial` | 已开始但被截断或无法继续解析的方向。offset 为已经交付的正文长度，调用方同时处理 API 的终止错误。每个已开始方向只交付一次终止事件。 |

`body_chunk`、`sse` 和下述 `grpc_message` 带正文数据。回调串行运行，channel 和回调速度对解密器施加背压。调用方取消 context 或让回调返回错误后，以 API 返回值作为终止信号。HTTP/1 固定长度和 chunked 正文按各自边界结束。close-delimited 响应在连接排空时区分已观察到的服务端 FIN / TLS close_notify 与只有抓包 EOF 的截断，后者交付 partial 并返回错误。

默认保留 Content-Encoding 的原始正文。将 `MaxDecodedBodyBytes` 设为正数（例如 `8 << 20`）会启用单层 gzip 的增量展开，值为每条消息的展开字节上限。此时 headers 带 `decoded_encoding="gzip"`，原始 Content-Length 和 Content-Encoding 仍描述线上编码。body、SSE 和 offset 均基于展开后的字节。超过额度或校验失败会终止该消息，已交付字节按 partial 处理。其他编码或组合编码原样交付 body。SSE 解析适用于未编码、identity 或成功选择 gzip 展开的正文。

HTTP/1 的初始头与 trailers、HTTP/2 的压缩/展开字段节、SSE 单行和累计 data 分别限制为 64 KiB。每连接最多 1024 个活动消息方向、16 个同时展开的 gzip 正文，HTTP/1 最多等待 1024 个响应，HTTP/2 最多保留 1024 个活动流和 1024 个 reset 标记。QUIC 按未消费和乱序字节计费，已交付正文不会积累成完整消息。H3 的 QPACK 等待和未关联 push 仍适用原缓存上限。超限报告 `resource_limit`，协议或内容解析失败报告 `protocol/parse_failed`。增量入口支持常规 HTTP/1、HTTP/2 和 HTTP/3，WebSocket/CONNECT 升级以及 HTTP/2 PUSH_PROMISE 仍有协议边界。SSE 事件字段依照 [HTML EventSource 规范](https://html.spec.whatwg.org/multipage/server-sent-events.html#event-stream-interpretation)。

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

真实 loopback 抓包覆盖 v1/v2 × AES-128-GCM/AES-256-GCM/ChaCha20-Poly1305 的双向更新。
原 AES-128 抓包包含多次更新；新增独立 aioquic 四个 AES-256/ChaCha 单元均验证双方
`0→1→0`、包号递增及原 header protection key 不变，另以标准库 HMAC 核对每次 secret 派生。
生成器针对固定版本的 v2 派生标签作了局部规范修正，不代表原版对端未经适配即可互通。
生成器修正、实际换代证据及命令见 [HTTP/3 fixture 说明](../test/fixtures/http3_capture/README.md#key-update-fixtures)。
TLS 1.3 的 KeyUpdate 使用独立的 record 状态机并重置序号，见 [TLS 版本与状态](#tls-版本与状态)；不能套用 QUIC 包号或密钥保留规则。

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
16 MiB 乱序字节与片段上限限制。流式 API 仍按既有背压契约交付，不启动无限输出队列。

独立真实夹具与固定向量覆盖 v1/v2 × AES-128-GCM/AES-256-GCM/ChaCha20-Poly1305。
实际 18 条连接产生 24 次请求/响应，其中 6 条经过迁移，6 条接受 early data，6 条拒绝后
以 1-RTT 重传；文件、内嵌 DSB、末尾 DSB 和 raw/messages 回放相互核对。
另有独立 v1/v2 × AES-128-GCM/AES-256-GCM/ChaCha20-Poly1305 的 Retry＋0-RTT 夹具：各版本/套件 seed/accepted/rejected，共 18 条连接，其中 12 条 early 连接在 Retry 前后使用同一 ClientHello/early key，改用新 DCID/token，包号不回退；拒绝后以 1-RTT 重发，raw 独立保留 rejected 字节，业务消息只交付一次。固定 aioquic 版本的测试适配保留握手状态并通过其原生丢包回调重排待重传内容，详情见 fixture 说明；SDK 不因此放宽认证。上述六个版本/套件单元同时覆盖 early 与握手密钥迟到、拒绝后的独立 raw 空间；draft-29 仍未通过真实捕获验证。


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

    // 采集时 argv；nil 表示未知，Data 为保留 NUL 分隔的原始字节
    ProcessArgs *ProcessArgs `json:"processArgs,omitempty"`
    
    // 数据长度
    DataLength uint32 `json:"dataLength"`
}
```

#### PID / PName 归属

文件和增量 pcapng API 均读取 eCapture 的以太网包尾元信息；它不是
EPB option 或 Custom Block。历史格式为大端 `0xCC0C4CFC`、uint32 PID、
uint8 Comm 长度及最多 16 字节 Comm，可带四字节全零 FCS 占位。
新格式在 Comm 后、FCS 前附加版本 `1` 和端点标志（`1`=包源端，
`2`=包目的端）。支持 IPv4/IPv6、VLAN 和最小以太网帧的零填充；
仅在 IP 声明的包尾边界解析，不扫描应用载荷中的魔数。

归属只表示采集端实际观察的本机进程，不表示远端进程。仅观察到一个
本机端点时，请求与响应使用该进程；loopback 两端均有可靠元信息时，
各方向使用发送端 PID/Comm。历史格式未标记端点，遇到不同 PID 时保留未知。
无元信息、格式不合法或同一端点归属冲突时，不通过 UUID/端口猜测 PID；
未知为 `PID=0, PName=""`，不再填写 `decryptor` 占位名称。

迟到元信息更新该连接代次的独立状态，影响后续回调；已经发出的回调不
回写。PID/Comm 不进入路由 key 或 ConnectionID，TCP 新 SYN/QUIC 新连接
的状态与旧代次隔离，保持双向关联和多连接路由。`ConnectionKey.Process`
只承载这一并发安全状态，不参与 JSON 序列化。该机制不能恢复采集端
漏掉的归属，也不保证共享 socket、多网络命名空间碰撞或不完整握手的归属。

`ProcessArgs` 含 `Data []byte` 和 `Truncated bool`（JSON 字段 `data`、
`truncated`）。文件及增量 API 读取同一包的标准 EPB comment：
`eCapture argv v1 <0|1> <base64>`。这是 argv 的独立扩展，PID/Comm 仍来自
上述包尾格式。`Data` 最多 256 字节，保留空参数、NUL 边界和非 UTF-8
字节，JSON 中为 base64；`Truncated=true` 时只含前 256 字节，末尾可能
处于某个参数中间。完整快照以 NUL 结束。缺失、重复或损坏的注释保持
argv 未知，不影响 PID/Comm 和解密。归属选择、迟到更新和连接代次隔离
沿用 PID/Comm 的规则；回调持有独立副本。它是发送时读取的 argv 快照，
不是不可变的最初 exec 参数；进程改写 argv 会影响后续快照。

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

上限：每方向实际动态表 64 KiB、每个解码字段节 64 KiB（按 name + value + 32 计）/1024 字段；每方向最多 64 条阻塞流，同时受对端 SETTINGS 限制。解析器最多保留 1024 个流标记、128 个 push；每个未关联 push 最多 16 个信息响应；待 SETTINGS 重放每方向最多 4096 个片段。连接内消息/流缓冲和待重放字节共 32 MiB，完整消息模式的单消息和 QUIC STREAM offset 上限为 16 MiB。超限返回终止错误并报告 `protocol/resource_limit`，不跳过失败断言或扩大缓存。

QPACK、SETTINGS 和消息顺序错误报告 `protocol/parse_failed`，不归为密码学认证失败。阻塞压缩/未关联 push 使用实际时间的 `KeyWaitTimeout`，逾期报告 `protocol/parse_timeout`；EOF 尚有不完整状态也返回错误。RESET、取消和关闭释放等待数据，正常结束仅保留有界去重/关联信息；输出继续遵守串行背压。缺失必要 encoder 历史或 SETTINGS 的片段捕获不能保证动态解码。长流使用下述 HTTP 增量事件契约。扩展 CONNECT、HTTP DATAGRAM 的应用关联与 WebTransport/MASQUE 尚未实现；底层 QUIC DATAGRAM 可显式 raw 输出，见 [数据报输出](#数据报输出)。

独立 `http3_dynamic_aioquic`（v1、AES-256-GCM）及 `http3_dynamic_aioquic_v2`（v2、AES-128-GCM）夹具各覆盖两条连接、双向动态表、延迟/拆分 encoder、103→200→trailers、push/reset；messages/raw/HTTPEvents、文件与迟到 DSB 均有回归。另有 `http3_early_reset_aioquic` 实测 v1/v2、AES-128-GCM 的 accepted/rejected 0-RTT RESET：40 字节非完整请求前缀后取消，拒绝时对端仅在 1-RTT 重发 RESET；完整消息不输出该 POST，HTTPEvents 仅为接受的前缀输出 body/reset，raw 保留独立 early 状态。后者不覆盖动态 QPACK 与 early RESET 的组合，也不扩大 Key Update 的真实套件矩阵。[复现步骤](../test/fixtures/http3_capture/README.md#dynamic-qpack-and-message-state-fixture)说明独立对端断言和抓包过程。

### WebSocket

默认完整消息模式支持 HTTP/1.1 Upgrade 后的 WebSocket。请求头跨 TLS record、同一 record 内的 101 与首帧、失败升级后的 HTTP/1 keep-alive 均可处理。握手校验 GET、HTTP/1.1、Host、Connection/Upgrade token、版本 13、16 字节 key、服务端 accept、子协议和扩展选择；非 101 响应仍按 HTTP 输出。

`Protocol="websocket"`，`Direction` 区分两端。按 `Metadata["kind"]` 区分输出：

| kind | Data 与元数据 |
| --- | --- |
| `upgrade` | 原始握手头，`upgrade="websocket"`、`headers`；请求另带 `method`/`url`，响应带 `status=101`。 |
| `message` | 完整 text/binary 消息字节，已去 mask、合并同方向 continuation、按协商展开压缩。`opcode`（byte）、`opcode_name`、`is_client`、`data_length`、`compressed`。text 必须是有效 UTF-8。 |
| `control` | ping/pong/close 的原始 payload，同样带 opcode/name/方向/长度。close 存在状态码时另带 `close_code`（uint16）和 `close_reason`。解析器被动读取，不发送 pong 或 close。 |

双向独立维护分片，控制帧可插入数据消息。客户端必须 mask、服务端不得 mask；拒绝非法 opcode/RSV、非最短长度、64 位高位、非法 continuation、控制帧分片或超过 125 字节，以及非法关闭码/UTF-8。握手头每方向最多 64 KiB，单帧、分片消息的编码总量和展开后的消息各最多 16 MiB。每方向只保留当前未完成消息和最多 32 KiB 压缩字典，不保存历史消息。发送使用背压，慢消费者不丢消息或控制帧。

支持按 [RFC 7692](https://www.rfc-editor.org/rfc/rfc7692.html) 协商的 `permessage-deflate`，含双向 context takeover、`client/server_no_context_takeover`、8–15 的 window bits。接收端使用 32 KiB 字典，也可解码协商了较小发送窗口的消息；不额外审计发送方实际使用的回溯距离。未协商压缩不能设置 RSV1，无法解释的服务端扩展会返回协议错误。超限为 `protocol/resource_limit`，非法帧/握手为 `protocol/parse_failed`；EOF 剩余半帧、未完成分片或未完成握手会返回错误。完整消息边界上的捕获 EOF 不要求一定看到 close 帧。

独立 Python websockets 夹具实测两个方向的压缩分片、控制帧和 takeover 开/关，详见 [复现步骤](../test/fixtures/http_tcp_capture/README.md#websocket-and-grpc-fixtures)。`HTTPEvents` 模式仍不接管 WebSocket Upgrade；HTTP/2、HTTP/3 的扩展 CONNECT 属于后续子项。

### gRPC（HTTP/2 增量语义）

显式选择 `HTTPEvents: true` 后，对 HTTP/2 `application/grpc` 或 `application/grpc+...` 自动解析五字节前缀。前缀和消息可跨 DATA/chunk，一片 DATA 也可包含多条消息。请求必须使用 POST；按连接、stream ID、方向独立编号。完整模式、HTTP/1、HTTP/3、gRPC-Web 不由此获得 gRPC 消息解析。

保留原有 HTTP headers/body_chunk/trailers/终止事件，headers 加 `grpc=true`。每条完整消息额外输出 `kind="grpc_message"`，`Protocol` 仍为 `http/2`；`Data` 是去掉五字节前缀、完成消息级解压后的原始消息字节，不需要 descriptor，也不推断 Protobuf 字段名。

- `message_index`（uint64）在每个流、方向从 0 开始，包括零长度消息。
- `offset`（uint64）是该消息前缀在 HTTP 正文中的起点；`wire_length`（uint32）是前缀声明的编码消息长度，不含前缀。HTTP body_chunk/终止 offset 仍描述完整线上正文。
- `compressed` 表示前缀标志；`grpc_encoding` 来自当前方向的 `grpc-encoding`，缺失时为 `identity`。支持未压缩消息及 gzip 消息压缩，每条消息独立解压并检查 gzip 校验。其他算法遇到 compressed=1 时明确失败，不输出伪解码结果。HTTP Content-Encoding 和 gRPC 消息压缩不混用；`MaxDecodedBodyBytes` 不控制 gRPC 消息限额。
- 响应 trailers 和 end 带 `grpc_status`（uint32）、百分号解码后的 `grpc_message`。非法百分号编码保留原值，`+` 保持字面含义；原始 headers/trailers（包括 `grpc-status-details-bin`）保留。非零业务状态正常交付，不作为解密错误。trailers-only 响应交付 headers、trailers、end。
- 缺少/畸形 `grpc-status`、截断前缀/body、非法压缩标志或压缩校验失败会返回解析错误，已开始方向终止为 partial。RESET 保留 HTTP/2 error_code、释放未完成消息，不将半条消息当作成功输出。SDK 不合成缺失的业务状态，也不解释 status-details 的 Protobuf。

单条编码消息和展开结果各限 16 MiB；每连接所有未完成 gRPC 消息的已接收 payload 共限 32 MiB，活动流仍适用 HTTP/2 限额。完整消息在 END_STREAM/EOF 前交付并释放，累计流长可超过 16 MiB。只拼接 body_chunk 才能还原 HTTP 正文，grpc_message 是额外语义视图。单元测试覆盖 unary/client/server/bidi streaming、长流和边界；独立 hyper-h2 + Python gzip 实际 TLS 流量覆盖四类调用、双向压缩、错误 trailers 和 trailers-only。基线为 [gRPC HTTP/2 协议](https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md)。

### TLS 版本与状态

TCP TLS 接受 TLS 1.2/1.3，必须有捕获到的 ClientHello、ServerHello 和对应 keylog；不会从任意密文位置猜测 record 序号，也不遍历其他连接的 secrets。cipher registry 的条目不等于所有版本/状态已经验证。此处的认证指 record AEAD/MAC（以及 ECH payload/accept_confirmation），不是完整的证书链、Finished transcript 或对端身份验证。

| 版本 / 套件 | 本仓库证据与范围 |
| --- | --- |
| TLS 1.3 AES-128-GCM/SHA256、AES-256-GCM/SHA384、ChaCha20-Poly1305/SHA256 | 三套件独立 KeyUpdate 派生向量、状态单测与真实 OpenSSL 抓包；每方向多次更新及 request_update，文件/尾部 DSB、messages/raw/HTTPEvents 逐字节回归。 |
| TLS 1.3 三套件状态矩阵 | 独立 OpenSSL 实测 HRR 拒绝 early、无 early 的 HRR 后 PSK 恢复、ECH＋HRR、ECH 接受且 HRR 拒绝 early 的三重组合。另有 AES-128 early → ChaCha20/AES-256 最终套件的 HRR 完整握手回退；不代表跨套件 PSK 恢复。 |
| TLS 1.3 AES-128-GCM/SHA256 | 独立真实普通 PSK 恢复、accepted/rejected early data、GREASE；Go 对端 ECH 接受/拒绝及各自与 HRR 的组合；OpenSSL 实测 ECH 拒绝且已发送 early、Inner/Outer 分别索引。ECH 拒绝＋HRR＋early 尚无合法真实夹具。 |
| TLS 1.2 AES-GCM/SHA256、AES-GCM/SHA384 | 独立双向记录向量覆盖 RSA、ECDHE-RSA、ECDHE-ECDSA 的对应记录算法；新增 ECDHE-RSA-AES256-GCM-SHA384 完整连接及恢复真实抓包。相同记录算法不等于已实测全部握手组合。 |
| TLS 1.2 AES-CBC/SHA、ChaCha20-Poly1305 | 有注册项/记录实现，尚未补齐独立实际状态矩阵；不承诺 Encrypt-then-MAC、重协商或任意组合可用。 |
| TLS 1.0/1.1、TLS 1.3 以外的 KeyUpdate | 不支持；旧版本被明确拒绝。 |

**TLS 1.3 KeyUpdate。** 使用初始 `CLIENT_TRAFFIC_SECRET_0` / `SERVER_TRAFFIC_SECRET_0`，收到当前方向已认证的完整 KeyUpdate 后，以 `traffic upd` 派生下一代 secret、key 和 IV，并将该方向 record 序号重置为 0；另一方向不跟随改变。`request_update` 只表示对端应答义务，被动解密器不发回复，也不提前替对端换代。只保留当前代，不接受 QUIC 式旧代回退；TCP 重传仍由 TCP 重组去重。坏认证、非法长度/请求值及跨越换代边界的内容不会推进代次。诊断为 `decrypt/key_update` / `key_update_requested`，不携带 secret。

**握手分帧与恢复。** 握手头可逐字节跨 record，单 record 可含多条消息；保留尾部，完整 Finished/KeyUpdate 到达才切换。每方向增量握手消息最多 1 MiB，明文 hello 读取还限制为 4,096 个 record；不增加无界累计历史。HRR 消费第二个 ClientHello 和最终 ServerHello，拒绝重复 HRR、版本/套件改变及有效 CH2 的 early_data 扩展；接受 ECH 时检查已认证的 Inner CH2，Outer CH2 可按 RFC 9849 复制该扩展。TLS 1.2/1.3 恢复仍需要当前连接 random 对应的 master/application secrets，不从 ticket 自行恢复密钥。支持 HRR＋普通 early data、ECH＋HRR 及 ECH 接受的三重组合。不宣称支持重协商或 post-handshake authentication。

**TLS early data。** ClientHello 的 early_data offer 启用独立客户端 early 阶段，需 `CLIENT_EARLY_TRAFFIC_SECRET`；普通流程用服务端 handshake secret 认证的 EncryptedExtensions 确认接受/拒绝；HRR 则强制拒绝 early data。EndOfEarlyData 在 early 密钥下认证，完整消息到达后切换至 handshake 阶段；确认接受但缺失该边界，或已拒绝却出现该消息，均会报错。正常应用消息及 HTTPEvents 仅交付确认接受的 early 字节，拒绝的 early 不进入应用 parser，后续 1-RTT 重发按正常数据处理。raw 保留已认证的 early：`encryption_level="0rtt"`，`early_data="accepted"|"rejected"|"unknown"`；该连接的正常 raw 标记 `encryption_level="1rtt"`。accepted early 与正常 request 共用连续 offset，rejected/unknown early 有独立的 request offset，不能拼接成已接受的正文。认证解密不保证服务端实际执行业务或防重放。

HRR 前已发送的 early record 按 TLS record 边界保留，最多 8 MiB，并与读取 CH2 共用原有 4,096 条 record 上限；不扫描密文寻找 ClientHello。它们仅用 early secret 认证并以 rejected raw 输出，不进入应用 parser；CH2 后从握手阶段处理，禁止 early/EndOfEarlyData 或 EE 再次接受 early。被拒绝的 early 可使用旧 ticket 的套件，与最终 ServerHello 不同；根据 early secret 的 hash 长度，仅尝试三种已支持 TLS 1.3 套件中的兼容候选（最多两个），首次 AEAD 认证后固定套件及序号。接受 early 时仍要求其套件与 ServerHello 相同；失败认证不推进序号。

缺少 early/handshake secrets 时保留有界密文，并由 keylog/末尾 DSB 唤醒；已从输入取出的待定 early record 最多一条（含头最多 65,540 字节），不能因 EE 拒绝便丢弃。只有 offer、未实际发送 early 时，可直接认证 handshake record，无需等待不存在的 early key。待接受状态确定的客户端明文最多 8 MiB/65,536 块，仍受初始 `KeyWaitTimeout` 总期限约束。未知接受状态在 EOF/期限到达时报告 `handshake/early_data_unknown` 并返回错误；raw 可保留标记 unknown 的已认证字节，应用模式不交付可能跨阶段的客户端消息。实际 early record 缺 secret 不伪造解密结果，会返回错误；可认证的其他方向数据仍按原契约保留。

**ECH 输入。** 按 [RFC 9850](https://www.rfc-editor.org/rfc/rfc9850.html#section-2.3)，`ECH_SECRET` 是 HPKE 的 KEM shared_secret，`ECH_CONFIG` 是单个 ECHConfig 的编码，两者必须用 **Outer ClientHello random** 索引；它们不是 TLS application secret 或 Inner random。当前支持 RFC 9849 ECH、X25519/HKDF-SHA256/AES-128-GCM HPKE（不代表 TLS record 必须用同一套件）。认证解开 payload、恢复 outer_extensions 并校验 ServerHello 的 accept_confirmation 后，接受时才改用 Inner random 查找 TLS secrets，拒绝时继续用 Outer random。ECH＋HRR 用 CH1 的 Outer random 查找 ECH 材料；接受时验证两次 payload（HPKE sequence 0/1）、HRR 的 `hrr ech accept confirmation` 和最终 ServerHello 的确认，transcript 按 `message_hash(CH1)` 重建，CH2 的 enc 为空且 Inner random 不变。拒绝/GREASE 的 CH2 保留完整原 ECH 扩展与 Outer random；缺 ECH 材料只允许该外层候选在 record 认证后标记未接受/未知，不推测 Inner random。损坏或错误关联、缺信息及其他 HPKE 参数都不会触发随机 secret 扫描。

ECH 的 early secret 始终按已认证 CH1 的 **Inner random** 查找，即使服务端拒绝 ECH、后续 handshake/application 改用 Outer random。ECH 接受＋HRR 的 Outer CH2 可保留 early_data，但 Inner CH2 必须移除；两次 ECH payload 及两次确认均需通过。实际 OpenSSL ECH 拒绝会在客户端导出 application secret 前中止；若已具备 Inner early 和 Outer 双向 handshake/server application secrets，可交付经认证的 rejected raw，仍报告 `handshake/ech_rejected` 及终止错误，不伪造 client application secret 或成功连接。

若仅有 Outer random 下的 TLS secrets、没有完整 ECH 标签，可尝试外层解密；带 early offer 的 GREASE 外层候选还需 Outer 的 early、双向 handshake 和 application secrets。只有 record 认证成功后才报告 `handshake/ech_not_accepted_or_grease`，不能据此区分真实拒绝与 GREASE。完全没有认证结果则报告 `ech_unknown`；有完整证据时为 `ech_accepted` / `ech_rejected`，ECH 解码失败为 `ech_unavailable`。缺少关联或必要 traffic secrets 保留终止错误，不输出未经认证的应用字节。普通 application-only keylog 仍可跳过有限的不可解 handshake record；始终未认证任何 application 候选时以 `decrypt/no_authenticated_application_data` 返回错误，不发送正常 raw 结束标记。

缺握手、中途接入、截断或丢失 record 无法保证恢复：分别保留 `missing_client_hello` / `invalid_server_hello`、`truncated_record` / `truncated_handshake`、认证或缺 secret 诊断及终止错误。SDK 不补猜缺失的 TLS 序号。规范依据 [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html)、[RFC 9849](https://www.rfc-editor.org/rfc/rfc9849.html)；[独立 TLS 发生器与复现方法](../test/fixtures/http_tcp_capture/README.md#d10-tls-state-fixtures)说明各项实测边界。

### TLSUpgrade

`types.DecryptOptions{TLSUpgrade: "smtp", RawChunks: true}` 为 TCP 显式选择一次明文协商后 TLS；`TLSUpgrade: "https-connect"` 为外层 TLS 内的 HTTP/1 CONNECT 再解密一层 TLS。空值保留直接 TLS 的原行为，不按端口猜测，也不扫描任意 `0x16`。该选项作用于本次调用的所有连接，仅 Go 文件/流式 API 提供；文件入口需并发消费 packet channel，QUIC/DoQ 不接受该选项。`RawChunks`、`HTTPEvents`、`ApplicationProtocol` 继续按各自互斥规则选择升级后最内层的输出。

| 值 | 本批协商范围与切换条件 |
| --- | --- |
| `smtp` | 服务端 greeting、EHLO/HELO、NOOP/RSET 与 STARTTLS；匹配完整最终 `220` 后切换，支持多行响应。DATA/AUTH/BDAT 等转入永久明文直通。 |
| `imap` | 未认证 greeting、CAPABILITY/NOOP、带 tag 的 STARTTLS；必须收到对应 tag 的 OK，不能由 untagged OK 触发。literal、认证和其他操作不继续寻找升级。 |
| `pop3` | 未认证 greeting、CAPA/NOOP、STLS；CAPA 多行以点终止；STLS 的完整 `+OK` 后升级，认证及其他操作保持明文。 |
| `ldap` | 首个操作为带 StartTLS OID 的 BER ExtendedRequest；匹配 message ID 的 ExtendedResponse resultCode=0 后切换。仅明确长度，不接受任意 BER 内容中的 OID 字样。 |
| `postgres` | 传统八字节 SSLRequest（80877103）与单字节 `S`；`N`/ErrorResponse 保持明文。GSSENCRequest、直接 TLS 协商另行处理。 |
| `mysql` | Protocol 10 greeting 声明 CLIENT_PROTOCOL_41/CLIENT_SSL，加序号 1 的 32 字节 SSLRequest；SSLRequest 之后立即切换，不等待不存在的明文成功响应。 |
| `connect` | 首轮 HTTP/1.0/1.1 CONNECT authority-form；任何 2xx 在响应头结束处切换，忽略成功响应的 Content-Length/Transfer-Encoding。 |
| `https-connect` | 先认证解密外层 TLS，执行同一 CONNECT 协商，最多再解密一层 TLS；两层共享 keylog，各自使用 ClientHello random 查找 secrets。 |

拒绝升级或遇到上述范围外的明文操作后，剩余字节持续作为明文直通，不在同一连接上再次尝试升级；失败后的伪 TLS 前缀不会进入 TLS 引擎。畸形协商返回错误；成功边界后同一块内的双向剩余字节精确交给既有 TLS 引擎。邮件/数据库选项只处理 TLS 协商，不增加对应应用消息解析器；这类载荷可用 `RawChunks`。HTTP/2/3 CONNECT、WebSocket 扩展 CONNECT、任意 Upgrade、重复代理认证及多层递归隧道不在此范围。

所有输出保留原物理连接的 `ConnectionID()`、地址和 `Generation`，以连接 ID 与 `tls_depth` 区分层：普通明文前导为 0，升级后 TLS 为 1；HTTPS CONNECT 外层为 1，内层为 2。非零层还带 `parent_tls_depth`，并带 `upgrade_protocol`（所选值）。前导输出 `Protocol="starttls"`、`kind="negotiation_chunk"`，`Data` 为按方向拼接可还原的协商/拒绝后原始字节，chunk 不是完整消息；深度 0 的字节未经 TLS 认证。

HTTPS CONNECT 始终额外输出 `Protocol="tls"`、深度 1 的已认证外层 raw chunks（含方向 offset 和结束事件），其中既有 CONNECT，也有承载内层 TLS 的线上字节；`starttls` 是同层协商的另一视图，不能把两者拼在一起。即使没有内层 secrets，已解出的外层字节仍然交付；内层握手/密钥未就绪而终止时报告固定 `tunnel/inner_tls_unavailable`，并保留终止错误。不会从内层密文伪造应用明文。

每方向待判定前导/候选最多 64 KiB，判定期间累计输入最多 1 MiB、最多 4,096 步；成功或拒绝后释放协商缓存，直通阶段不累计历史数据。每层沿用 TLS 每方向 8 MiB 输入上限；一个物理连接最多一个内层解密器及一个有界输出转发器，父连接额度直到两层退出才释放。`KeyWaitTimeout` 从升级 worker 启动统一限制协商、外层与内层握手/密钥等待，阶段切换不延期，成功获得内层密钥或明确保持明文后停止该计时；之后仍有空闲回收。嵌套内层等待超时后结束内层，已就绪的外层继续交付到 EOF/空闲回收，最终仍返回内层错误。半条协商 EOF 返回错误，取消/回调失败沿用排空与背压契约。

独立 [STARTTLS/CONNECT 夹具](../test/fixtures/http_tcp_capture/README.md#d09-tls-upgrade-and-connect-fixtures) 使用 Python 标准库 TLS/MemoryBIO 和真实 loopback 抓包，覆盖七类明文协商及 HTTPS CONNECT 的成功/拒绝连接、TLS 1.3 双向字节、外层/内层独立 secrets、文件和尾部 DSB 流式路径。协商规范依据 [RFC 3207](https://www.rfc-editor.org/rfc/rfc3207.html)、[RFC 2595](https://www.rfc-editor.org/rfc/rfc2595.html)、[RFC 4511](https://www.rfc-editor.org/rfc/rfc4511.html#section-4.14)、[PostgreSQL SSL 协商](https://www.postgresql.org/docs/current/protocol-flow.html#PROTOCOL-FLOW-SSL)、[MySQL SSLRequest](https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_ssl_request.html) 和 [RFC 9110 CONNECT](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6)。

### ApplicationProtocol

Go 文件和流式 API 可通过 `types.DecryptOptions{ApplicationProtocol: "doh"}` 显式选择应用协议。允许值为 `dot`、`doh`、`doq`、`mqtt`、`redis`；空值保留现有 HTTP/WebSocket 识别。该选择作用于本次解密的连接，不是端口过滤器，也不自动按端口切换协议。它与 `RawChunks`、`HTTPEvents`、非零 `MaxDecodedBodyBytes` 互斥；非法值和选项冲突在读取输入前返回错误。文件入口必须提供并发消费的 packet channel；流式入口沿用串行回调和背压。CLI/C 示例尚未增加这些选项。

```go
err := ecapture_decryptor.DecryptPcapngStreamWithOptions(ctx, input, emit,
    types.DecryptOptions{ApplicationProtocol: "doh"})
// 文件入口：config.WithOptions(types.DecryptOptions{ApplicationProtocol: "doh"})
```

`dot`、`mqtt`、`redis` 用于 TLS/TCP；`doh` 用于 HTTP/1.x、HTTP/2 或 HTTP/3；`doq` 用于 QUIC。UDP/QUIC 上选择 TCP 专用协议、TLS 上选择 `doq` 会失败。QUIC 在解密握手并观察到服务端 ALPN 时检查其是否匹配：DoQ 要求 `doq`，HTTP/3/DoH 要求 `h3`（也识别 `h3-29`，不扩大 draft-29 的实测范围）。缺少握手 secrets 时无法检查协商结果，显式选择是调用方对协议的声明；未知协议可使用 raw 输出。各 parser 的错误和资源超限仍分别报告 `protocol/parse_failed`、`protocol/resource_limit`，终止错误不被诊断替代。

#### DNS

三种传输均支持普通 DNS QUERY，拒绝 AXFR/IXFR 和其他 opcode。校验完整 wire 长度、名称/压缩指针、记录边界和 OPT 位置；未知 RR 的内容保留在线上字节中，不提供完整的 RR 类型语义。`Protocol="dns"`，`Data` 为完整 DNS wire message，不含 DoT/DoQ 的两字节长度或 HTTP framing。

- **DoT**：两字节长度前缀可跨 TLS record，支持粘连和流水线。按连接、DNS ID、问题名称/类型/类配对，名称匹配忽略 ASCII 大小写；同 ID 的不同问题可逆序返回。响应没有唯一候选时输出 `matched=false`，不猜测关联。无 question 的错误响应也必须只有唯一候选。
- **DoH**：GET 的单个 `dns` 参数使用无填充 base64url；POST 及成功响应要求无参数的 `application/dns-message`。只接受未编码/identity 正文，不展开 HTTP gzip。按 HTTP 请求/stream 关联并核对 DNS ID 和问题；完整 HTTP 消息结束后交付 DNS。非 2xx 最终响应输出空 `Data` 的 `kind="http_error"` 和整数 `status`，不伪装成 DNS 响应。取消释放关联状态；不支持 HTTP push。
- **DoQ**：仅支持 1-RTT。每条客户端发起的双向流恰好包含一个请求和一个响应，均为两字节长度前缀且 DNS ID 必须为 0；每方向在 FIN 验证完整性后输出。拒绝单向/服务端发起流、流复用和 EDNS TCP keepalive。响应先到时有界等待请求并核对问题。RESET_STREAM 输出空 `Data` 的 `kind="reset"`、`error_code`（uint64），释放该事务；完成和 reset 标记保留用于去重。

正常消息的 `kind="message"`。用 `ConnectionID()`、`request_id` 和方向关联事务，不能只用 DNS ID：

| 元数据 | 类型与含义 |
| --- | --- |
| `transport` | `dot`、`doh` 或 `doq`；外层 `DecryptedPacket.Transport` 仍为 `tcp`/`udp`。 |
| `id`、`opcode`、`rcode` | uint16；`rcode` 包含 EDNS 扩展响应码。`qr`、`truncated` 为 bool。 |
| `questions`、`answers` | `[]map[string]any`；问题含 `name`、`type`/`class`（uint16），答案另含 `ttl`（uint32），常见 RR 还含 `address`、`target`、`preference` 或 `text`。四个 section 的 `*_count` 为 int。 |
| `request_id` | uint64，限本连接：DoT 从 1 编号，仅已关联响应携带；DoH 使用 HTTP 请求编号/stream ID；DoQ 为 `stream_id/4+1`。 |
| `matched` | bool；成功关联的响应为 true。DoT 未匹配响应为 false；请求不表示配对已完成。 |
| `stream_id` | DoH/DoQ 的 uint64；DoH HTTP/1 从 1 编号，HTTP/2、3 与 DoQ 使用线上 stream ID。DoH 另带 `http_protocol`；DoQ 消息带 `stream_end=true`。 |

每条 DNS wire 最多 65,535 字节、64 个问题、四个 section 合计 1,024 条记录。DoT 最多 1,024 个待配对请求和 1 MiB 问题关联数据。DoH 待请求/待响应各最多 1,024 条，共享 4 MiB 正文/关联字节预算，另有最多 1,024 个取消标记，并受底层 HTTP 头部、流和 QPACK 上限约束。DoQ 最多 1,024 个流标记（含已完成/reset）、4 MiB 缓冲及 1 MiB 问题关联数据，仍受 QUIC 重组上限约束。EOF 半条 DNS 报文会报错；DoH/DoQ 尚未完成的事务也会报错，DoT 在完整报文边界允许尚无响应。独立 TLS/QUIC 发生器见 [DNS 夹具说明](../test/fixtures/http3_capture/README.md)。

#### MQTT

`ApplicationProtocol: "mqtt"` 支持 TLS 内的 MQTT **3.1.1**，要求观察到客户端 CONNECT；支持 CONNECT/CONNACK、双向 PUBLISH（QoS 0/1/2）、订阅/退订及其确认、PUBACK/PUBREC/PUBREL/PUBCOMP、PINGREQ/PINGRESP 和 DISCONNECT。校验固定头、最短 Remaining Length、包方向、UTF-8 字符串及 topic/filter。MQTT 5、MQTT over WebSocket 不在此入口范围内。解析器不跟踪 ACK 事务状态、不合并 DUP 重发，也不推断 exactly-once 投递结果。

`Protocol="mqtt"`，`Data` 保留完整控制包（含固定头和 payload）。`kind` 为 `control`、`publish`、`subscribe` 或 `unsubscribe`；`packet_type`（byte）、`packet_name` 描述包类型，`message_index`（uint64）在每方向从 0 编号。PUBLISH 含 `topic`、`qos`（byte）、`dup`/`retain`（bool），QoS > 0 时含 `packet_id`（uint16）；`payload_offset`/`payload_length`（int）定位 `Data` 内的业务字节。订阅包含 `topics`、`requested_qos`，确认包保留 `packet_id` 和相应返回码；CONNECT 含 `protocol_level`、`keep_alive`、`client_id`、`clean_session`、`will`。这些字段描述已观察到的报文，不构成请求/响应配对。

完整包及每方向缓冲各最多 16 MiB；单包 topic/返回码列表最多 1,024 项。完整包输出后释放，不累计历史包。EOF 半包返回错误；完整包边界无需看到 CONNACK、后续 ACK 或 DISCONNECT。`Data` 可能包含 CONNECT 凭据及二进制业务内容，元数据不额外复制密码。独立真实 TLS 夹具见 [TCP 夹具说明](../test/fixtures/http_tcp_capture/README.md)。

#### Redis

`ApplicationProtocol: "redis"` 支持 TLS 内以 bulk string 数组编码的命令，以及定长 RESP2/RESP3 值，包括嵌套聚合、map/set、RESP3 push/attribute。普通响应按连接内请求顺序配对；Pub/Sub 订阅确认可对应同一请求的多个确认，消息推送和 attribute 不消耗普通响应位置。RESP2 Pub/Sub 分类依赖已观察到的订阅状态，RESP3 使用显式 push 类型。不支持 inline 命令、流式/未知长度 RESP、MONITOR、复制命令（SYNC/PSYNC/REPLCONF）及 CLIENT REPLY。

`Protocol="redis"`，`Data` 为原始完整 RESP 值，保留二进制字符串，不新增递归值对象；AUTH 等命令的凭据也保留在原始字节中。`kind` 为 `request`、`response`、`push` 或 `attribute`，`resp_type` 为线上首字符。请求含从 1 开始的 `request_id`（uint64）、大写 `command`、`argument_count`（int）；已配对响应带相同 ID/命令，早到的普通响应有界等待请求成帧；EOF 仍没有候选时输出 `unsolicited=true`。订阅确认等待对应命令，普通 RESP3 push 和 attribute 不等待。push 含 `push_type`；订阅确认另带 `subscription_count`（int）及可关联的 ID/命令。attribute 独立交付，不合并进后续值。

每个编码后的完整值最多 16 MiB，单行 64 KiB、嵌套深度 32、元素数 65,536；命令名最多 128 字节。每连接待响应请求和订阅各最多 1,024 项，订阅键总计最多 64 KiB；早到响应队列最多 1,024 个完整值、合计 16 MiB。完整值持续交付后释放，累计连接流量不受单值限额限制。EOF 半个值或尚有待响应请求返回错误，已建立的订阅本身不导致 EOF 错误。独立真实 TLS 夹具见 [TCP 夹具说明](../test/fixtures/http_tcp_capture/README.md)。

---

## 🔐 支持的协议

| 协议 | Protocol 字段 | 支持程度 | 说明 |
|------|---------------|----------|------|
| HTTP/1.1 | `http/1.1` | ✅ 完整 | 包括 chunked 编码 |
| HTTP/2 | `http/2` | ✅ 完整 | 帧解析、流重组 |
| HTTP/3 | `http/3` | ✅ 有界消息解析 | QUIC + 动态 QPACK；边界见上节 |
| WebSocket | `websocket` | ✅ HTTP/1 Upgrade | 双向分片、控制帧、permessage-deflate；边界见上节 |
| gRPC | `http/2` + `grpc_message` | ✅ 显式增量语义 | HTTPEvents；未压缩/gzip 消息与状态 trailers |
| DNS | `dns` | ✅ 显式选择 | DoT、DoH（HTTP/1.x、2、3）、DoQ（1-RTT）；普通 QUERY |
| MQTT | `mqtt` | ✅ 显式选择 | TLS 内 MQTT 3.1.1 控制包；不跟踪 ACK 投递状态 |
| Redis | `redis` | ✅ 显式选择 | TLS 内定长 RESP2/RESP3、流水线配对及 Pub/Sub |

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
| `unsupported protocol` | 不支持的协议或版本 | 核对 TLS、QUIC 或显式 DTLS 的支持矩阵及选项 |
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

