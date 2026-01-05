#!/bin/bash
# test_client_all.sh - 综合测试脚本 (macOS/Linux 兼容)
# 使用多种 HTTP 客户端: curl, wget, nc (netcat), python


# sudo ./ecapture tls -m keylog
# tcpdump -i any -w /tmp/capture.pcap port 443 &
set -e

HOST="local.koujue.cc"
PORT="443"
URL="https://${HOST}"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

success() { echo -e "${GREEN}✓${NC}"; }
fail() { echo -e "${RED}✗${NC} $1"; }
info() { echo -e "${YELLOW}$1${NC}"; }

# 检查命令是否存在
check_cmd() {
    command -v "$1" >/dev/null 2>&1
}

# 随机等待 1-2 秒
random_sleep() {
    if [[ "$(uname)" == "Darwin" ]]; then
        # macOS: 使用 jot 生成随机数
        sleep_time=$(jot -r 1 1 2)
    else
        # Linux: 使用 shuf
        sleep_time=$(shuf -i 1-2 -n 1)
    fi
    sleep ${sleep_time}
}

echo "=========================================="
echo "  HTTP 协议测试脚本 (macOS/Linux)"
echo "  目标: ${URL}"
echo "=========================================="
echo ""

# ============================================
# 使用 curl 测试
# ============================================
echo "========== [curl] HTTP Protocol Tests =========="

echo -n "[curl] HTTP/1.0 GET: "
curl -k -s -0 ${URL}/ > /dev/null && success || fail
random_sleep

echo -n "[curl] HTTP/1.1 GET: "
curl -k -s --http1.1 ${URL}/ > /dev/null && success || fail
random_sleep

echo -n "[curl] HTTP/2 GET: "
curl -k -s --http2 ${URL}/ > /dev/null && success || fail
random_sleep

echo ""
echo "========== [curl] POST Tests =========="

echo -n "[curl] POST JSON: "
curl -k -s -X POST -H "Content-Type: application/json" -d '{"test":1}' ${URL}/api/post > /dev/null && success || fail
random_sleep

echo -n "[curl] POST Form: "
curl -k -s -X POST -d "key=value&name=test" ${URL}/api/post > /dev/null && success || fail
random_sleep

echo ""
echo "========== [curl] Upload Tests =========="

# 创建测试文件 (macOS 兼容: 使用 m 小写或直接指定字节数)
TEST_FILE="/tmp/test_5m.bin"
if [[ "$(uname)" == "Darwin" ]]; then
    # macOS
    dd if=/dev/zero of=${TEST_FILE} bs=1048576 count=5 2>/dev/null
else
    # Linux
    dd if=/dev/zero of=${TEST_FILE} bs=1M count=5 2>/dev/null
fi

echo -n "[curl] Upload 5M file: "
curl -k -s -X POST -F "file=@${TEST_FILE}" ${URL}/api/upload > /dev/null && success || fail
random_sleep

echo ""
echo "========== [curl] Special Response Tests =========="

echo -n "[curl] Redirect (302): "
code=$(curl -k -s -w "%{http_code}" -o /dev/null ${URL}/redirect)
[ "$code" = "302" ] && success || fail "got $code"
random_sleep

echo -n "[curl] Redirect follow: "
curl -k -s -L ${URL}/redirect > /dev/null && success || fail
random_sleep

echo -n "[curl] Gzip response: "
curl -k -s -H "Accept-Encoding: gzip" ${URL}/gzip | gunzip > /dev/null 2>&1 && success || fail
random_sleep

echo ""
echo "========== [curl] Status Code Tests =========="
for code in 200 201 400 404 500; do
    echo -n "[curl] Status $code: "
    result=$(curl -k -s -w "%{http_code}" -o /dev/null ${URL}/status/$code)
    [ "$result" = "$code" ] && success || fail "got $result"
    random_sleep
done

# ============================================
# 使用 wget 测试
# ============================================
echo ""
echo "========== [wget] HTTP Tests =========="

if check_cmd wget; then
    echo -n "[wget] GET /: "
    wget --no-check-certificate -q -O /dev/null ${URL}/ && success || fail
    random_sleep

    echo -n "[wget] GET /api/info: "
    wget --no-check-certificate -q -O /dev/null ${URL}/api/info && success || fail
    random_sleep

    echo -n "[wget] POST data: "
    wget --no-check-certificate -q -O /dev/null --post-data="key=value" ${URL}/api/post && success || fail
    random_sleep

    echo -n "[wget] Download file: "
    wget --no-check-certificate -q -O /tmp/wget_test.bin ${URL}/files/test.txt 2>/dev/null && success || fail "file may not exist"
    rm -f /tmp/wget_test.bin
    random_sleep

    echo -n "[wget] Upload file: "
    wget --no-check-certificate -q -O /dev/null --post-file=${TEST_FILE} \
        --header="Content-Type: application/octet-stream" ${URL}/api/upload && success || fail
    random_sleep
else
    info "[wget] 未安装，跳过 (brew install wget)"
fi

# ============================================
# 使用 Python requests 测试
# ============================================
echo ""
echo "========== [python] HTTP Tests =========="

if check_cmd python3; then
    # HTTP/1.1 GET
    echo -n "[python] GET request: "
    python3 -c "
import urllib.request
import ssl
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
req = urllib.request.Request('${URL}/')
resp = urllib.request.urlopen(req, context=ctx)
print(resp.status, end='')
" 2>/dev/null && success || fail
    random_sleep

    # POST JSON
    echo -n "[python] POST JSON: "
    python3 -c "
import urllib.request
import ssl
import json
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
data = json.dumps({'test': 1}).encode('utf-8')
req = urllib.request.Request('${URL}/api/post', data=data, method='POST')
req.add_header('Content-Type', 'application/json')
resp = urllib.request.urlopen(req, context=ctx)
print(resp.status, end='')
" 2>/dev/null && success || fail
    random_sleep

    # 文件上传
    echo -n "[python] Upload file: "
    python3 << EOF 2>/dev/null && success || fail
import urllib.request
import ssl
import os

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# 构建 multipart 数据
boundary = '----WebKitFormBoundary7MA4YWxkTrZu0gW'
filename = '${TEST_FILE}'

with open(filename, 'rb') as f:
    file_data = f.read()

body = (
    '--' + boundary + '\r\n'
    'Content-Disposition: form-data; name="file"; filename="test.bin"\r\n'
    'Content-Type: application/octet-stream\r\n\r\n'
).encode('utf-8') + file_data + ('\r\n--' + boundary + '--\r\n').encode('utf-8')

req = urllib.request.Request('${URL}/api/upload', data=body, method='POST')
req.add_header('Content-Type', 'multipart/form-data; boundary=' + boundary)
resp = urllib.request.urlopen(req, context=ctx)
print(resp.status, end='')
EOF
    random_sleep

else
    info "[python] python3 未安装，跳过"
fi

# ============================================
# 使用 nc (netcat) 原始 HTTP 请求测试
# ============================================
echo ""
echo "========== [nc/openssl] Raw HTTP Tests =========="

# 通过 openssl s_client 发送原始 HTTP 请求
echo -n "[openssl] Raw HTTP/1.0 GET: "
response=$(echo -e "GET / HTTP/1.0\r\nHost: ${HOST}\r\n\r\n" | \
    openssl s_client -connect ${HOST}:${PORT} -quiet 2>/dev/null | head -1)
echo "$response" | grep -q "HTTP/1" && success || fail "$response"
random_sleep

echo -n "[openssl] Raw HTTP/1.1 GET: "
response=$(echo -e "GET / HTTP/1.1\r\nHost: ${HOST}\r\nConnection: close\r\n\r\n" | \
    openssl s_client -connect ${HOST}:${PORT} -quiet 2>/dev/null | head -1)
echo "$response" | grep -q "HTTP/1.1" && success || fail "$response"
random_sleep

echo -n "[openssl] Raw POST: "
POST_DATA='{"test":"raw"}'
response=$(echo -e "POST /api/post HTTP/1.1\r\nHost: ${HOST}\r\nContent-Type: application/json\r\nContent-Length: ${#POST_DATA}\r\nConnection: close\r\n\r\n${POST_DATA}" | \
    openssl s_client -connect ${HOST}:${PORT} -quiet 2>/dev/null | head -1)
echo "$response" | grep -q "HTTP/1.1" && success || fail "$response"
random_sleep

# ============================================
# 使用 HTTPie 测试 (如果安装)
# ============================================
echo ""
echo "========== [httpie] HTTP Tests =========="

if check_cmd http; then
    echo -n "[httpie] GET request: "
    http --verify=no GET ${URL}/ > /dev/null 2>&1 && success || fail
    random_sleep

    echo -n "[httpie] POST JSON: "
    http --verify=no POST ${URL}/api/post test=1 > /dev/null 2>&1 && success || fail
    random_sleep

    echo -n "[httpie] POST form: "
    http --verify=no --form POST ${URL}/api/post key=value > /dev/null 2>&1 && success || fail
    random_sleep
else
    info "[httpie] 未安装，跳过 (brew install httpie)"
fi

# ============================================
# 清理
# ============================================
echo ""
echo "========== Cleanup =========="
rm -f ${TEST_FILE}
echo "临时文件已清理"

echo ""
echo "=========================================="
echo "  All tests completed!"
echo "=========================================="
