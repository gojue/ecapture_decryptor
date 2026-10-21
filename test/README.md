# 测试数据

`testdata/` 中 `http10_*`、`http11_*`、`http2_*`、`http3_*` 的 pcapng
是在 Linux VM 上执行抓包命令取得的真实网络包。
对应的流量程序和复现命令：

- [HTTP/1.0、HTTP/1.1、HTTP/2 TCP 抓包](fixtures/http_tcp_capture/README.md)：短连接、长连接、分块传输及多路复用；每个场景包含 tcpdump 外部 SSLKEYLOG 和 eCapture 内嵌 DSB。
- [HTTP/3 QUIC 抓包](fixtures/http3_capture/README.md)：回环地址和公网域名；同样覆盖外部 SSLKEYLOG 与内嵌 DSB。

`curl_clients_external_keylog.pcapng` 则从已有的真实抓包
`all_clients.pcap` 中筛出完整的 curl TCP 连接（stream 1、2、3、9），
再转换成 pcapng；未合成网络包。它使用已有的
`all_clients_sslkey.log`，覆盖 curl 的 HTTP/1.0、HTTP/1.1、HTTP/2
和 `/gzip` 请求。重建该夹具的命令：

```sh
tshark -r test/testdata/all_clients.pcap \
  -Y 'tcp.stream == 1 || tcp.stream == 2 || tcp.stream == 3 || tcp.stream == 9' \
  -w test/testdata/curl_clients_external_keylog.pcapng
```

`examples/test_e2e.py` 会解密该 pcapng，生成 `curl_clients.har`，并核对
HAR 中的 curl User-Agent、协议版本、URL、状态码和响应正文。

端到端测试还会将真实抓包作为非 seekable 输入，检查流式处理、外部
SSLKEYLOG 与内嵌 DSB 共同加载，以及 `DecryptPcapngStream` 回调。
运行并打印各条解密结果最多 100 字节的预览：

```sh
go test -run 'TestDecryptTCPHTTPCaptures|TestDecryptHTTP3QUICCapture|TestDecryptPcapngStreamCapturedTraffic' -v .
```

示例程序的构建与真实抓包端到端验证（Go CLI、Go static demo、C 离线/流式程序、
C live demo 的未实现错误路径）需要 Go、Python 3 和 C 编译器，可在 Linux 或
macOS 上运行：

```sh
make -C examples test
```

默认的 HAR/JSON 输出在临时目录中，测试结束会删除。要保留文件供查看：

```sh
python3 examples/test_e2e.py --output-dir test/result
```
