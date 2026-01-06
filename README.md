# eCapture Decryptor - TLS/QUIC 流量解密库

一个用于解密 TLS/QUIC 加密流量的 Go 语言库，支持多种应用层协议解析。

## ✨ 特性

- 🔓 **解密 TLS/QUIC 流量**：使用 SSLKEYLOG 文件解密 HTTPS/QUIC 流量
- 🌐 **多协议支持**：HTTP/1.1, HTTP/2, HTTP/3, WebSocket
- 📦 **灵活输出**：输出 `DecryptedPacket` 结构，用户可自由处理
- 🔧 **多种使用方式**：Go 库、静态链接库（.a）、命令行工具
- 🎯 **职责清晰**：只负责解密和协议解析，不强制输出格式

## 🚀 快速开始

### 安装

```bash
go get github.com/cfc4n/ecapture_decryptor
```

### 基本使用

```go
package main

import (
    "log"
    "os"
    
    "github.com/cfc4n/ecapture_decryptor"
    "github.com/cfc4n/ecapture_decryptor/types"
)

func main() {
    // 打开文件
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
                packet.Protocol,    // "http/1.1", "http/2", etc.
                packet.Direction,   // "request" or "response"
                len(packet.Data))   // 解密后的数据
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

## 📦 构建

```bash
# 构建示例程序（Go API，已优化体积）
make build

# 构建静态链接库 (.a 文件，供 C/C++ 使用)
make build-lib

# 构建 C 示例程序（使用静态库）
make build-c-demo

# 构建并使用 UPX 压缩（额外减小 50-60% 体积）
make build-compressed

# 对比不同优化级别的体积
make build-compare

# 清理
make clean
```

构建产物：
- `bin/ecapture_decryptor` - 命令行工具（Go）
- `bin/libecapture_decryptor.a` - 静态链接库
- `bin/libecapture_decryptor.h` - C 头文件
- `examples/c_demo/offline_decryption` - C 离线解密示例
- `examples/c_demo/stream_decryption` - C 流式解密示例
- `examples/c_demo/live_capture_simple` - C 实时捕获示例

### 📉 体积优化

默认构建已应用以下优化（减少 30-40% 体积）：
- `-s -w`: 去除符号表和调试信息
- `-trimpath`: 去除文件系统路径

## 🎯 命令行使用

```bash
# 基本使用 - 输出统计信息
./bin/ecapture_decryptor \
  -pcap traffic.pcap \
  -sslkeylog sslkey.log \
  -v

# 保存为 HAR 格式
./bin/ecapture_decryptor \
  -pcap traffic.pcap \
  -sslkeylog sslkey.log \
  -har output.har

# 保存为 JSON 格式
./bin/ecapture_decryptor \
  -pcap traffic.pcap \
  -sslkeylog sslkey.log \
  -json output.json
```

## 📊 DecryptedPacket 结构

```go
type DecryptedPacket struct {
    Protocol     string                 // 协议: "http/1.1", "http/2", "http/3", "websocket"
    Direction    string                 // 方向: "request" 或 "response"
    Data         []byte                 // 解密后的应用层数据
    Timestamp    time.Time              // 数据包时间戳
    ConnectionID string                 // 连接标识符
    Metadata     map[string]interface{} // 协议特定元数据
}
```

### 元数据示例

**HTTP/1.1 Request:**
```go
{
    "method": "GET",
    "url": "https://example.com/path",
    "headers": http.Header{...}
}
```

**HTTP/2:**
```go
{
    "stream_id": 1,
    "method": "GET",
    "path": "/path",
    "headers": http.Header{...}
}
```

## 🔧 API 参考

### 核心函数

#### DecryptPcapFile
解密 pcap/pcapng 文件中的流量

```go
func DecryptPcapFile(
    keylogReader io.Reader,      // SSLKEYLOG 文件
    pcapFileHandle io.Reader,    // PCAP 文件
    packetChan chan *types.DecryptedPacket, // 输出 channel
) error
```

#### DecryptLiveTraffic
解密实时流量（从网卡或实时 pcap 流）

```go
func DecryptLiveTraffic(
    keylogReader io.Reader,      // SSLKEYLOG 文件
    pcapHandle io.Reader,        // 实时 pcap 流
    packetChan chan *types.DecryptedPacket, // 输出 channel
) error
```

## 🔗 C/C++ 静态库使用

### 构建静态库

```bash
make build-lib
```

这将生成：
- `bin/libecapture_decryptor.a` - 静态库
- `bin/libecapture_decryptor.h` - C 头文件

### C API 函数

#### 离线解密
- `GetVersion()` - 获取库版本
- `DecryptPcapToFile()` - 解密 pcap 文件到 JSON
- `FreeString()` - 释放 Go 分配的字符串

#### 实时/流式解密
- `DecryptPcapStreamToFile()` - 从 stdin 解密 pcap 流（可用于管道）
- `DecryptLiveTrafficToFile()` - 启动实时流量解密（非阻塞）
- `StopLiveTraffic()` - 停止实时流量解密
- `GetLiveTrafficError()` - 获取实时会话错误信息

### C 程序示例

#### 1. 离线解密

```c
#include "libecapture_decryptor.h"
#include <stdio.h>

int main() {
    char errorBuf[256] = {0};
    int ret = DecryptPcapToFile(
        "./traffic.pcap",
        "./sslkey.log",
        "./output.json",
        "json",
        errorBuf,
        sizeof(errorBuf)
    );
    
    if (ret != 0) {
        fprintf(stderr, "Decryption failed: %s\n", errorBuf);
        return 1;
    }
    
    printf("Success!\n");
    return 0;
}
```

#### 2. 流式解密（从管道）

```c
// 从 tcpdump 管道读取并解密
// 用法: tcpdump -i eth0 -w - | ./stream_decrypt sslkey.log output.json

int main(int argc, char *argv[]) {
    char errorBuf[256] = {0};
    int ret = DecryptPcapStreamToFile(
        argv[1],  // keylog path
        argv[2],  // output path
        0,        // maxPackets (0 = unlimited)
        errorBuf,
        sizeof(errorBuf)
    );
    
    if (ret != 0) {
        fprintf(stderr, "Stream decryption failed: %s\n", errorBuf);
        return 1;
    }
    
    return 0;
}
```

#### 3. 实时流量捕获

```c
// 启动实时捕获 30 秒
int handle = DecryptLiveTrafficToFile(
    "en0",          // 网卡名称
    "sslkey.log",   // keylog 文件
    "output.json",  // 输出文件
    errorBuf,
    sizeof(errorBuf)
);

if (handle > 0) {
    sleep(30);  // 捕获 30 秒
    StopLiveTraffic(handle);
}
```

### 完整 C 示例程序

项目包含完整的 C 示例程序，演示了所有功能：

```bash
# 构建 C 示例程序
make build-c-demo

# 运行测试
cd examples/c_demo
make test

# 离线解密
./offline_decryption traffic.pcap sslkey.log output.json

# 流式解密（从文件）
cat traffic.pcap | ./stream_decryption sslkey.log output.json

# 流式解密（从 tcpdump）
tcpdump -i eth0 -w - | ./stream_decryption sslkey.log output.json

# 实时捕获（API 演示）
./live_capture_simple en0 sslkey.log output.json 30
```

查看 `examples/c_demo/README.md` 获取详细说明。


### 编译 C/C++ 程序

```bash
# Linux/macOS
gcc -o myapp myapp.c \
    -I./bin -L./bin \
    -lecapture_decryptor \
    -lpthread -lresolv

# C++
g++ -o myapp myapp.cpp \
    -I./bin -L./bin \
    -lecapture_decryptor \
    -lpthread -lresolv
```

**详细文档**: 查看 [docs/CAPI_USAGE.md](docs/CAPI_USAGE.md) 获取完整的 C API 使用说明。

## 📝 示例程序

项目包含完整的示例程序，展示如何：
- 解密流量并输出统计信息
- 将解密结果转换为 HAR 格式
- 将解密结果保存为 JSON

查看 `examples/` 目录获取更多示例。

## 🏗️ 架构

### 数据流架构

```mermaid
flowchart TD
    A[PCAP 文件/实时流量] --> B[Packet Source<br/>数据包源]
    B --> C[Connection Tracker<br/>连接跟踪器]
    
    C --> D{协议类型}
    D -->|TCP/TLS| E[TLS Decryptor<br/>TLS 1.2/1.3 解密]
    D -->|UDP/QUIC| F[QUIC Decryptor<br/>QUIC 解密]
    
    G[SSLKEYLOG 文件] --> H[KeyLog Store<br/>密钥存储]
    H --> E
    H --> F
    
    E --> I[Protocol Parser<br/>协议解析器]
    F --> I
    
    I --> J{应用层协议}
    J -->|HTTP/1.1| K[HTTP/1.1 Parser]
    J -->|HTTP/2| L[HTTP/2 Parser]
    J -->|HTTP/3| M[HTTP/3 Parser]
    J -->|WebSocket| N[WebSocket Parser]
    
    K --> O[DecryptedPacket<br/>解密数据包]
    L --> O
    M --> O
    N --> O
    
    O --> P[Output Channel<br/>输出通道]
    
    P --> Q{用户处理}
    Q --> R[HAR 转换器]
    Q --> S[JSON 输出]
    Q --> T[自定义处理]
    
    style A fill:#e1f5ff
    style O fill:#fff4e1
    style P fill:#e8f5e9
    style H fill:#f3e5f5
```

### 分层架构

```mermaid
graph TB
    subgraph Application["应用程序层"]
        APP[Go 应用 / C/C++ 应用]
    end
    
    subgraph API["公开 API 层"]
        API1[DecryptPcapFile]
        API2[DecryptLiveTraffic]
        API3[DecryptWithConfig]
    end
    
    subgraph Protocol["协议解析层 protocol/"]
        HTTP1[HTTP/1.1 Parser]
        HTTP2[HTTP/2 Parser]
        HTTP3[HTTP/3 Parser]
        WS[WebSocket Parser]
    end
    
    subgraph Transport["传输层解密 transport/"]
        TLS[TLS Decryptor<br/>TLS 1.2/1.3]
        QUIC[QUIC Decryptor]
    end
    
    subgraph Crypto["密码学层 crypto/"]
        KeyLog[KeyLog Store<br/>密钥管理]
        Cipher[Cipher Registry<br/>密码套件]
        Decrypt[Record Decryptor<br/>记录解密]
    end
    
    subgraph Capture["数据包捕获层"]
        GoPacket[gopacket<br/>pcap/pcapng 解析]
    end
    
    APP --> API
    API --> Protocol
    Protocol --> Transport
    Transport --> Crypto
    Crypto --> Capture
    
    style Application fill:#e3f2fd
    style API fill:#f3e5f5
    style Protocol fill:#e8f5e9
    style Transport fill:#fff3e0
    style Crypto fill:#fce4ec
    style Capture fill:#f1f8e9
```

## 📚 文档

### 核心文档
- **[CHANGELOG.md](CHANGELOG.md)** - 版本变更历史
- **[快速开始](#-快速开始)** - 使用示例（见上方）

### 技术文档 (在 docs/ 目录)
- **[API 参考](docs/API.md)** - 完整 API 文档和使用指南
- **[架构设计](docs/ARCHITECTURE.md)** - 系统架构和设计原理
- **[开发指南](docs/DEVELOPMENT.md)** - 开发环境和贡献指南

### 构建和发布 (在 docs/ 目录)
- **[Makefile 指南](docs/MAKEFILE_GUIDE.md)** - 构建系统使用说明
- **[发布管理](docs/RELEASE_GUIDE.md)** - 版本发布完整流程
- **[发布快速参考](docs/RELEASE_QUICKREF.md)** - 常用发布命令
- **[发布示例](docs/RELEASE_EXAMPLES.md)** - 真实场景示例
- **[文档索引](docs/README.md)** - 完整文档导航

### 许可证文档
- **[LICENSE](LICENSE)** - 主许可证（中英文）
- **[LICENSE-BINARY](LICENSE-BINARY)** - 二进制库许可证（中英文）
- **[COPYRIGHT](COPYRIGHT)** - 版权声明
- **[许可摘要](docs/LICENSE-SUMMARY.md)** - 许可证快速参考

## 📄 许可证 / License

### ⚠️ 双重许可模式 / Dual License

本项目采用**双重许可模式**：

#### 1. 源代码许可 (Source Code License)

**版权所有 © 2024-2026 CFC4N (cfc4n.cs@gmail.com)。保留所有权利。**

源代码为**专有软件**，未经明确书面许可，**禁止任何形式的使用、复制、修改或分发**。

查看源代码不授予任何使用权限。

#### 2. 二进制库许可 (Binary Library License)

**版权所有 © 2024-2026 CFC4N (cfc4n.cs@gmail.com)。保留所有权利。**

编译后的二进制库（.a, .so, .dylib）可用于**非商业用途**：

✅ **允许**：
- 个人使用
- 研究和教育用途
- 评估和测试
- 与非商业应用程序链接

❌ **禁止**：
- 商业使用（需要单独商业许可）
- 反向工程、反编译或修改
- 破解或规避功能
- 重新分发修改版本
- 删除版权声明

📝 **必需**：
- 保留所有版权声明
- 在您的应用程序中提供署名
- 包含许可证文件

#### 署名要求 / Attribution

使用本库时，必须包含以下署名：

```
本软件使用 eCapture Decryptor 库
版权所有 (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com)
授权用于非商业用途
https://github.com/cfc4n/ecapture_decryptor
```

#### 商业许可 / Commercial License

如需商业使用，请联系：
- **邮箱**: cfc4n.cs@gmail.com
- **主题**: "Commercial License Inquiry - eCapture Decryptor"

#### 详细许可条款 / Detailed Terms

- [LICENSE](LICENSE) - 完整许可证（中英文）
- [LICENSE-BINARY](LICENSE-BINARY) - 二进制库详细许可（中英文）
- [COPYRIGHT](COPYRIGHT) - 版权声明

## 🤝 贡献

由于源代码为专有软件，暂不接受外部贡献。

如有问题或建议，欢迎提交 Issue。

## 🙏 致谢

本项目基于以下优秀的开源项目：
- [gopacket](https://github.com/google/gopacket) - 数据包处理
- Go 标准库的 crypto/tls 包

---

**⚠️ 重要提示**：
1. 使用本工具需要有合法的 SSLKEYLOG 文件
2. 请确保你有权限解密目标流量
3. 遵守所有适用的法律法规
4. 商业使用需要获得单独授权

**Copyright © 2024-2026 CFC4N. All Rights Reserved.**


