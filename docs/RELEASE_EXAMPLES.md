# 发布系统使用示例

本文档提供完整的发布系统使用示例，帮助你快速上手。

## 📝 场景 1: 发布小版本更新 (Bug 修复)

你修复了一些 bug，需要发布 v1.0.1 版本。

```bash
# 1. 查看当前版本
./scripts/version.sh show
# 输出: Current version: v1.0.0

# 2. 升级 patch 版本
./scripts/version.sh bump patch
# ✓ Version bumped to v1.0.1

# 3. 编辑 CHANGELOG.md 添加修复的内容
vim CHANGELOG.md
# 在 [v1.0.1] 部分添加:
# ### Fixed
# - Fixed memory leak in QUIC decryptor
# - Corrected HTTP/3 header parsing

# 4. 运行测试
make test

# 5. 提交更改
git add .
git commit -m "Release v1.0.1 - Bug fixes"

# 6. 创建并推送标签
git tag v1.0.1
git push origin main --tags

# 7. GitHub Actions 自动发布完成！
# 访问: https://github.com/gojue/ecapture_decryptor/releases
```

---

## 🎉 场景 2: 发布新功能版本

你添加了新功能，需要发布 v1.1.0 版本。

```bash
# 1. 升级 minor 版本
./scripts/version.sh bump minor
# ✓ Version bumped to v1.1.0

# 2. 更新 CHANGELOG.md
vim CHANGELOG.md
# 添加新功能描述:
# ### Added
# - Support for TLS 1.3 0-RTT decryption
# - New API function `DecryptWithOptions()`
# ### Changed
# - Improved HTTP/2 parsing performance by 30%

# 3. 更新 README.md (如果需要)
# 添加新功能的使用说明

# 4. 运行完整测试
make test
make fmt
make lint

# 5. 本地测试发布（可选）
make release VERSION=v1.1.0

# 6. 验证发布包
cd dist/ecapture_decryptor-v1.1.0-darwin-arm64
cat README.md
ls -la lib/

# 7. 提交并发布
cd ../..
git add .
git commit -m "Release v1.1.0 - New features"
git tag v1.1.0
git push origin main --tags
```

---

## 🚨 场景 3: 发布破坏性变更版本

API 有重大变更，需要发布 v2.0.0。

```bash
# 1. 升级 major 版本
./scripts/version.sh bump major
# ✓ Version bumped to v2.0.0

# 2. 详细记录破坏性变更
vim CHANGELOG.md
# ### ⚠️ Breaking Changes
# - Removed deprecated `DecryptOld()` function
# - Changed API signature of `DecryptPcapFile()`
# - Requires Go 1.21+ (previously 1.19+)
#
# ### Migration Guide
# - Replace `DecryptOld()` with `DecryptPcapFile()`
# - Update function calls to match new signature

# 3. 更新文档
# - 更新 README.md
# - 更新 examples/
# - 添加迁移指南

# 4. 充分测试
make test
cd examples && make test

# 5. 提交并发布
git add .
git commit -m "Release v2.0.0 - Major version with breaking changes"
git tag v2.0.0
git push origin main --tags
```

---

## 🧪 场景 4: 发布预发布版本 (Beta/RC)

你想发布一个测试版本让用户试用。

```bash
# 1. 设置预发布版本号
./scripts/version.sh set v1.1.0-beta.1

# 2. 更新 CHANGELOG
vim CHANGELOG.md
# ## [v1.1.0-beta.1] - 2026-01-06
# ### Added (Preview)
# - Experimental support for WebSocket decryption

# 3. 本地构建测试
make release VERSION=v1.1.0-beta.1

# 4. 提交
git add .
git commit -m "Release v1.1.0-beta.1 - Beta release"
git tag v1.1.0-beta.1
git push origin main --tags

# 5. 在 GitHub Release 中标记为 Pre-release
# 或使用 CLI:
gh release create v1.1.0-beta.1 \
  --title "v1.1.0-beta.1 (Beta)" \
  --notes "Beta release for testing" \
  --prerelease \
  dist/*.tar.gz
```

---

## 🔄 场景 5: 多平台同时发布

需要为所有平台构建发布包。

```bash
# 1. 准备版本
./scripts/version.sh set v1.1.0
vim CHANGELOG.md

# 2. 使用多平台构建脚本
./scripts/build-multiplatform.sh v1.1.0
# 这会使用 Docker 构建:
# - darwin-amd64
# - darwin-arm64
# - linux-amd64
# - linux-arm64

# 3. 验证所有构建包
ls -lh dist/*.tar.gz
sha256sum dist/*.tar.gz

# 4. 创建 Release 并上传所有包
gh release create v1.1.0 \
  --title "ecapture_decryptor v1.1.0" \
  --notes-file RELEASE_NOTES.md \
  dist/*.tar.gz \
  dist/*.sha256
```

---

## 🛠️ 场景 6: 仅发布当前平台

只需要发布 macOS ARM64 版本。

```bash
# 1. 准备版本
./scripts/version.sh set v1.1.0

# 2. 仅构建当前平台
make release VERSION=v1.1.0

# 3. 查看生成的文件
ls -la dist/
# ecapture_decryptor-v1.1.0-darwin-arm64.tar.gz
# ecapture_decryptor-v1.1.0-darwin-arm64.tar.gz.sha256

# 4. 创建 Release
gh release create v1.1.0 \
  --title "ecapture_decryptor v1.1.0 (macOS ARM64)" \
  dist/ecapture_decryptor-v1.1.0-darwin-arm64.*
```

---

## 📦 场景 7: 手动打包发布

需要自定义发布包内容。

```bash
# 1. 构建库
make clean
make build-static
make build-shared

# 2. 创建发布目录
VERSION="v1.1.0"
PLATFORM="darwin-arm64"
RELEASE_DIR="dist/ecapture_decryptor-${VERSION}-${PLATFORM}"
mkdir -p "${RELEASE_DIR}"/{lib,include,docs}

# 3. 复制文件
cp lib/libecapture_decryptor.a "${RELEASE_DIR}/lib/"
cp lib/libecapture_decryptor.dylib "${RELEASE_DIR}/lib/"
cp include/libecapture_decryptor.h "${RELEASE_DIR}/include/"
cp LICENSE* COPYRIGHT "${RELEASE_DIR}/"

# 4. 添加自定义内容
cp -r examples/c_demo "${RELEASE_DIR}/docs/examples"
echo "Custom build for special users" > "${RELEASE_DIR}/NOTES.txt"

# 5. 生成校验和
cd "${RELEASE_DIR}"
find . -type f -exec sha256sum {} \; > SHA256SUMS

# 6. 打包
cd ..
tar -czf "ecapture_decryptor-${VERSION}-${PLATFORM}.tar.gz" \
  "ecapture_decryptor-${VERSION}-${PLATFORM}"
sha256sum "ecapture_decryptor-${VERSION}-${PLATFORM}.tar.gz" \
  > "ecapture_decryptor-${VERSION}-${PLATFORM}.tar.gz.sha256"
```

---

## 🔍 场景 8: 验证发布包

用户下载后如何验证和使用。

```bash
# 1. 下载发布包
wget https://github.com/gojue/ecapture_decryptor/dist/download/v1.1.0/ecapture_decryptor-v1.1.0-darwin-arm64.tar.gz
wget https://github.com/gojue/ecapture_decryptor/dist/download/v1.1.0/ecapture_decryptor-v1.1.0-darwin-arm64.tar.gz.sha256

# 2. 验证校验和
sha256sum -c ecapture_decryptor-v1.1.0-darwin-arm64.tar.gz.sha256

# 3. 解压
tar -xzf ecapture_decryptor-v1.1.0-darwin-arm64.tar.gz
cd ecapture_decryptor-v1.1.0-darwin-arm64

# 4. 验证内容
sha256sum -c SHA256SUMS

# 5. 查看文档
cat README.md

# 6. 编译示例
gcc -o test docs/examples/offline_decryption.c \
    -I./include -L./lib -lecapture_decryptor \
    -framework CoreFoundation -framework Security

# 7. 运行测试
./test path/to/test.pcap path/to/keylog.log output.json
```

---

## 🆘 常见问题处理

### 问题 1: 版本号设置错误

```bash
# 回滚版本号
./scripts/version.sh set v1.0.0

# 或手动编辑
vim capi/main.go
```

### 问题 2: 构建失败

```bash
# 清理并重试
make clean
rm -rf dist/
./scripts/release.sh v1.1.0
```

### 问题 3: 标签推送错误

```bash
# 删除本地标签
git tag -d v1.1.0

# 删除远程标签
git push origin :refs/tags/v1.1.0

# 重新创建
git tag v1.1.0
git push origin v1.1.0
```

### 问题 4: GitHub Actions 失败

```bash
# 查看 Actions 日志
gh run list
gh run view <run-id>

# 手动触发
gh workflow run release.yml
```

---

## 📊 发布后检查

```bash
# 1. 验证 GitHub Release 页面
open https://github.com/gojue/ecapture_decryptor/releases

# 2. 验证下载链接
curl -I https://github.com/gojue/ecapture_decryptor/dist/download/v1.1.0/...

# 3. 检查统计数据
gh api repos/gojue/ecapture_decryptor/dist/latest

# 4. 更新项目主页
vim README.md
# 更新 "最新版本" 链接
```

---

**提示**: 建议在正式发布前，先在测试仓库中练习整个流程。

**联系**: cfc4n.cs@gmail.com

