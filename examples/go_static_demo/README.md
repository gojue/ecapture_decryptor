# Go Static Library Demo - 静态库调用演示

这个示例演示了与 C demo 等价的功能，但由于技术限制使用 Go API 实现。

## 功能说明

这个程序提供与 C demo 完全相同的功能：
- 读取 pcap 文件
- 使用 SSL keylog 文件解密 TLS/SSL 流量
- 将解密结果输出为 JSON 格式

## 技术说明

### 为什么不使用 CGO 直接链接静态库？

原本计划使用 CGO 链接 `libecapture_decryptor.a` 静态库，但遇到技术限制：

**问题**: Go 的 c-archive 构建模式会将整个 Go 运行时编译进静态库。当另一个 Go 程序尝试通过 CGO 链接这个静态库时，会出现符号冲突（两个 Go 运行时）：

```
duplicate symbol '__cgo_topofstack'
duplicate symbol '_crosscall2'  
duplicate symbol '__cgo_panic'
```

**解决方案**: 
- **C/C++ 程序**: 可以直接链接使用（见 `c_demo`）✅
- **Go 程序**: 使用 Go API 直接调用（本示例）✅
- **其他语言**: 可以使用动态库 (.so/.dylib) 或 RPC 方式

### 本示例的实现方式

本示例直接使用 Go API (`github.com/gojue/ecapture_decryptor`)，这样：
1. ✅ 避免了 CGO 符号冲突问题
2. ✅ 提供与 C demo 完全相同的命令行接口和行为
3. ✅ 性能更好（无 CGO 调用开销）
4. ✅ 代码更简洁，更易维护

## 与 go_demo 的区别

| 特性 | go_demo | go_static_demo (本目录) |
|------|---------|----------------------|
| 使用方式 | 库形式使用 | 独立命令行工具 |
| 接口风格 | Go API 风格 | C demo 命令行风格 |
| 适用场景 | Go 项目中集成 | 独立使用/脚本调用 |
| 命令行接口 | Go 风格参数 | 与 C demo 一致 |

## 编译要求

- Go 1.19 或更高版本
- 无需 CGO（纯 Go 实现）

## 构建步骤

### 直接构建

```bash
cd examples/go_static_demo
make build
```

或者从项目根目录：

```bash
make -C examples/go_static_demo build
```

生成的二进制文件：`bin/go_static_decryptor`

## 使用方法

### 基本用法

```bash
./bin/go_static_decryptor -pcap <pcapng文件> [-keylog <keylog文件>] [-output <输出文件>]
```

### 参数说明

- `-pcap` : pcap 文件路径（必需）
- `-keylog` : 外部 SSL keylog 文件路径（可选；省略时使用 pcapng 内嵌 DSB）
- `-output` : 输出 JSON 文件路径（可选，默认：output.json）
- `-format` : 输出格式（目前只支持 json）
- `-version` : 显示库版本信息

### 示例

#### 1. 解密 pcap 文件

```bash
./bin/go_static_decryptor \
  -pcap ./test/testdata/all_clients.pcap \
  -keylog ./test/testdata/all_clients_sslkey.log \
  -output result.json
```

#### 2. 查看版本信息

```bash
./bin/go_static_decryptor -version
```

#### 使用 pcapng 内嵌 DSB

```bash
./bin/go_static_decryptor -pcap traffic-with-dsb.pcapng -output result.json
```

#### 3. 使用 Makefile 测试

```bash
cd examples/go_static_demo
make test
```

## 代码说明

### 核心实现

使用 Go API 进行解密：

```go
// 打开文件
keylogFd, _ := os.Open(keylogFile)
pcapFd, _ := os.Open(pcapFile)

// 创建数据包通道
packetChan := make(chan *types.DecryptedPacket, 100)

// 解密
err := decryptor.DecryptPcapFile(keylogFd, pcapFd, packetChan)

// 收集结果并写入 JSON
```

### 命令行接口

提供与 C demo 一致的命令行接口：
- `-pcap`: pcap 文件路径
- `-keylog`: 可选的外部 SSL keylog 文件路径
- `-output`: 输出文件路径
- `-version`: 显示版本

## 技术特点

1. **命令行兼容**: 与 C demo 保持一致的命令行接口
2. **纯 Go 实现**: 无 CGO 依赖，编译简单
3. **跨平台**: 天然支持所有 Go 支持的平台
4. **高性能**: 无 CGO 调用开销

## 平台支持

- ✅ macOS (Darwin)
- ✅ Linux
- ✅ Windows  
- ✅ FreeBSD
- ✅ 其他 Go 支持的平台

## 故障排除

### 找不到 Go 模块

```
cannot find package "github.com/gojue/ecapture_decryptor"
```

**解决方案**：确保在项目根目录下，Go 模块已初始化
```bash
cd /path/to/ecapture_decryptor
go mod download
```

## 输出格式

输出 JSON 包含解密后的数据包数组，每个数据包包含：

```json
[
  {
    "timestamp": "2024-01-05T10:30:45.123456Z",
    "src_ip": "192.168.1.100",
    "dst_ip": "93.184.216.34",
    "src_port": 54321,
    "dst_port": 443,
    "protocol": "TCP",
    "decrypted_data": "GET / HTTP/1.1\r\nHost: example.com\r\n...",
    "data_length": 256
  }
]
```

## 使用场景

- ✅ 作为命令行工具独立使用
- ✅ 在 shell 脚本中批量处理 pcap 文件
- ✅ 与其他命令行工具配合使用（管道）
- ✅ 学习和理解解密流程
- ✅ 提供与 C demo 一致的用户体验

## 参考

- [go_demo](../go_demo/) - Go API 库形式使用示例
- [c_demo](../c_demo/) - C 语言静态库使用示例（推荐 C/C++ 项目）
- [项目主 README](../../README.md)

## 真正的 CGO 集成

如果你需要在非 Go 语言中使用这个库：
- **C/C++ 项目**: 使用 [c_demo](../c_demo/) 中的方法，直接链接 `libecapture_decryptor.a`
- **Python/Ruby 等**: 可以考虑使用动态库 (.so/.dylib) 或通过子进程调用
- **Go 项目**: 直接使用 Go API（最佳方案）


