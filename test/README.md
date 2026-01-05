test/
├── testdata/
│   ├── http1/
│   │   ├── simple_get.pcap
│   │   ├── post_json.pcap
│   │   ├── large_file.pcap
│   │   ├── chunked.pcap
│   │   └── sslkeys_http1.log
│   ├── http2/
│   │   ├── h2_simple.pcap
│   │   ├── h2_multiplex.pcap
│   │   └── sslkeys_http2.log
│   ├── websocket/
│   │   ├── ws_handshake.pcap
│   │   ├── ws_messages.pcap
│   │   └── sslkeys_ws.log
│   └── mixed/
│       ├── all_protocols.pcap   # 包含所有协议的综合测试
│       └── sslkeys_all.log