# Release Guide - 发布指南

本文档说明如何发布不同版本的动态、静态链接库。以下版本号为示例，命令从仓库根目录执行；构建需要 Go 1.26.0 或兼容的更新版本及 C 编译器。

## 📦 发布流程 Release Process

### 1. 准备发布 Prepare Release

#### 更新版本号 Update Version

使用 `./scripts/version.sh set v2.1.0` 更新 `capi/main.go` 中的版本号，并填写生成的 CHANGELOG 条目。`GetVersion()` 的字符串前缀为：

```go
func GetVersion() *C.char {
    return C.CString("eCapture Decryptor v2.1.0 - Copyright (c) 2024-2026 CFC4N - Non-Commercial License")
}
```

#### 更新 CHANGELOG

在 `CHANGELOG.md` 中记录版本变更：

```markdown
## [v2.1.0] - 2026-01-05

### Added
- 新功能描述

### Changed  
- 变更说明

### Fixed
- 修复的问题
```

#### 更新文档

- 更新 README.md 中的版本信息
- 更新示例代码中的版本引用
- 检查所有文档的准确性

### 2. 构建发布 Build Release

#### 单平台构建 Single Platform Build

```bash
# 为当前平台构建
./scripts/release.sh v2.1.0
```

这将创建：
- `dist/ecapture_decryptor-v2.1.0-<platform>/` - 解压后的目录
- `dist/ecapture_decryptor-v2.1.0-<platform>.tar.gz` - 压缩包
- `dist/ecapture_decryptor-v2.1.0-<platform>.tar.gz.sha256` - 校验和

#### 多平台构建 Multi-Platform Build

```bash
# 使用 Docker 为多个平台构建
./scripts/build-multiplatform.sh v2.1.0
```

脚本先构建当前主机平台，再使用 Go 1.26 Docker 镜像分别构建 `linux/amd64` 和 `linux/arm64`。Docker 必须能够运行对应架构的容器（原生运行或已配置模拟）；它不会交叉构建另一种 macOS 架构。没有 Docker 时只构建本机平台。

GitHub Release 工作流当前构建 `linux-amd64`、`linux-arm64` 和 `darwin-arm64`，不包含 `darwin-amd64`。直接设置 `GOOS`/`GOARCH` 做 CGO 交叉编译时，还需匹配的目标 C 工具链；仅设置这两个变量不够。

### 3. 测试发布 Test Release

```bash
# 在 macOS ARM64 上测试本机发布包；示例源码来自同版本仓库
cd dist/ecapture_decryptor-v2.1.0-darwin-arm64
cc -o test ../../examples/c_demo/offline_decryption.c \
  -I./include ./lib/libecapture_decryptor.a -lpthread \
  -framework CoreFoundation -framework Security

# 运行测试
./test path/to/test.pcap path/to/keylog.log output.json

# 验证输出
cat output.json
cd ../..
```

Linux 上将两个 `-framework` 参数替换为 `-lresolv`。测试程序必须在与发布包兼容的平台和架构上运行；标准发布包不含示例源码。

### 4. 创建 GitHub Release

推送 `v*.*.*` 标签会触发 `.github/workflows/release.yml`，自动构建并创建 Release。以下 CLI 和网页操作用于手动发布，不要对工作流已创建的同一版本重复执行 `gh release create`。

#### 使用 GitHub CLI

```bash
# 创建 release
gh release create v2.1.0 \
  --title "ecapture_decryptor v2.1.0" \
  --notes "Release notes here" \
  dist/ecapture_decryptor-v2.1.0-*.tar.gz \
  dist/ecapture_decryptor-v2.1.0-*.tar.gz.sha256

# 或使用 notes 文件
gh release create v2.1.0 \
  --title "ecapture_decryptor v2.1.0" \
  --notes-file RELEASE_NOTES.md \
  dist/ecapture_decryptor-v2.1.0-*.tar.gz \
  dist/ecapture_decryptor-v2.1.0-*.tar.gz.sha256
```

#### 手动上传

1. 访问 https://github.com/gojue/ecapture_decryptor/releases/new
2. 填写版本标签：`v2.1.0`
3. 填写标题：`ecapture_decryptor v2.1.0`
4. 添加 Release Notes
5. 上传所有 `.tar.gz` 文件和 `.sha256` 文件
6. 选择是否为预发布版本
7. 点击 "Publish release"

### 5. 发布公告 Announce Release

- 更新项目 README 中的最新版本链接
- 在 GitHub Discussions 发布公告
- 如有需要，在社交媒体宣传

---

## 📋 发布清单 Release Checklist

使用此清单确保发布过程完整：

### 发布前 Pre-Release

- [ ] 代码已合并到 master 分支
- [ ] 所有测试通过 (`CGO_ENABLED=1 go test -race ./...`)
- [ ] 更新版本号在 `capi/main.go`
- [ ] 更新 `CHANGELOG.md`
- [ ] 更新 `README.md` 中的版本信息
- [ ] 检查许可证文件是否最新
- [ ] 改动的 Go 文件通过 gofmt 和 goimports 检查
- [ ] 静态检查通过 (`make lint`)

### 构建 Build

- [ ] 清理旧构建 (`make clean`)
- [ ] 运行发布脚本 (`./scripts/release.sh vX.Y.Z`)
- [ ] 验证生成的文件完整性
- [ ] 检查 SHA256 校验和
- [ ] 测试构建的库

### 发布 Release

- [ ] 创建 Git 标签
- [ ] 推送标签到 GitHub
- [ ] 创建 GitHub Release
- [ ] 上传所有平台的构建包
- [ ] 上传 SHA256 校验和文件
- [ ] 填写 Release Notes

### 发布后 Post-Release

- [ ] 验证下载链接可用
- [ ] 测试从 Release 下载并使用
- [ ] 更新文档网站（如有）
- [ ] 发布公告
- [ ] 关闭相关的 Issues 和 Milestones

---

## 🏷️ 版本命名规范 Versioning Scheme

我们使用 [Semantic Versioning](https://semver.org/) (语义化版本):

```
vMAJOR.MINOR.PATCH

v2.1.0
│ │ │
│ │ └─ PATCH: 向后兼容的bug修复
│ └─── MINOR: 向后兼容的新功能
└───── MAJOR: 不兼容的API变更
```

### 版本号规则

- **MAJOR**: 主版本号，不兼容的 API 更改
  - 破坏性变更
  - API 重大重构
  - 示例：`v1.0.0` → `v2.0.0`

- **MINOR**: 次版本号，向后兼容的功能新增
  - 新增功能
  - 新增 API
  - 性能改进
  - 示例：`v2.0.0` → `v2.1.0`

- **PATCH**: 修订版本号，向后兼容的问题修复
  - Bug 修复
  - 文档更新
  - 小的改进
  - 示例：`v2.1.0` → `v2.1.1`

### 预发布版本 Pre-Release Versions

```
v2.1.0-alpha.1   # Alpha 版本
v2.1.0-beta.1    # Beta 版本
v2.1.0-rc.1      # Release Candidate
```

`version.sh set` 接受有或没有 `v` 前缀的 `X.Y.Z`，以及预发布后缀或构建元数据（如 `2.1.0-rc.1+build.2`）。`bump` 只处理无后缀的正式版本；从预发布版本转为正式版时，用 `set` 明确指定目标版本。

Release 工作流当前固定 `prerelease: false`，不会按标签后缀自动标记预发布。工作流完成后需在 GitHub 上修改，或运行 `gh release edit v2.1.0-beta.1 --prerelease`。

---

## 📚 发布包内容 Release Package Contents

每个发布包包含：

```
ecapture_decryptor-v2.1.0-darwin-arm64/
├── lib/
│   ├── libecapture_decryptor.a        # 静态库
│   └── libecapture_decryptor.dylib    # 动态库
├── include/
│   └── libecapture_decryptor.h        # C 头文件
├── LICENSE                            # 主许可证
├── LICENSE-BINARY                     # 二进制库许可证
├── COPYRIGHT                          # 版权声明
├── README.md                          # 使用说明
└── SHA256SUMS                         # 文件校验和
```

Linux 包中的动态库名为 `libecapture_decryptor.so`。标准包没有 `docs/` 或 `examples/`；C 示例位于同版本源码的 `examples/c_demo/`。

---

## 🔐 签名和验证 Signing and Verification

### 生成 GPG 签名

```bash
# 为 release 创建签名
gpg --armor --detach-sign dist/ecapture_decryptor-v2.1.0-darwin-arm64.tar.gz

# 验证签名
gpg --verify dist/ecapture_decryptor-v2.1.0-darwin-arm64.tar.gz.asc
```

### 验证 SHA256

```bash
# 验证单个文件
sha256sum -c ecapture_decryptor-v2.1.0-darwin-arm64.tar.gz.sha256

# 验证包内所有文件
cd ecapture_decryptor-v2.1.0-darwin-arm64
sha256sum -c SHA256SUMS
```

macOS 可将 `sha256sum` 替换为 `shasum -a 256`。

---

## 🌐 不同平台的特殊说明

### macOS

**依赖框架**:
- CoreFoundation
- Security

**代码签名** (可选):
```bash
codesign -s "Developer ID" lib/libecapture_decryptor.dylib
```

### Linux

**依赖库**:
- pthread
- resolv

当前脚本生成未带版本后缀的 `libecapture_decryptor.so`，不生成版本化 SONAME 或对应符号链接。

### Windows (如需支持)

当前发布脚本和 Release 工作流不包含 Windows 构建；不能将 Linux/macOS 的验证结果视为 Windows 支持。

---

## 📊 发布统计 Release Metrics

### 跟踪指标

- 下载量
- 使用平台分布
- 反馈和 Issues
- 商业许可咨询

### 监控

```bash
# 使用 GitHub API 获取下载统计
gh api repos/gojue/ecapture_decryptor/releases/latest
```

---

## 🆘 故障排除 Troubleshooting

发布脚本的隔离回归可用 `python3 scripts/test_release.py` 运行：它在临时副本中模拟构建和 Docker 调用，不执行实际发布；CI 在 Ubuntu/macOS 上运行同一检查。

### 构建失败

```bash
# 清理并重试
make clean
rm -rf dist/
./scripts/release.sh v2.1.0
```

### 测试失败

```bash
# 检查依赖
ldd lib/libecapture_decryptor.so  # Linux
otool -L lib/libecapture_decryptor.dylib  # macOS
```

### 上传失败

```bash
# 重新上传特定文件
gh release upload v1.1.0 dist/ecapture_decryptor-v1.1.0-darwin-arm64.tar.gz --clobber
```

---

## 📞 支持 Support

发布相关问题请联系：
- Email: cfc4n.cs@gmail.com
- Issues: https://github.com/gojue/ecapture_decryptor/issues

---

**最后更新**: November 7, 2026

**维护者**: CFC4N

