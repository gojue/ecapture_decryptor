# Quick Release Reference - 快速发布参考

以下版本号为示例，命令从仓库根目录执行。构建需要 Go 1.26.0 或兼容的更新版本及 C 编译器。

## 🚀 快速发布流程

### 1. 准备发布

```bash
# 查看当前版本
./scripts/version.sh show

# 自动升级版本号（小版本）
./scripts/version.sh bump minor

# 或手动设置版本号
./scripts/version.sh set v2.1.0

# 编辑 CHANGELOG.md 填写变更内容
vim CHANGELOG.md
```

### 2. 测试和验证

```bash
# 运行完整 race 测试
CGO_ENABLED=1 go test -race ./...

# 发布脚本回归（临时副本，模拟构建和 Docker，不执行发布）
python3 scripts/test_release.py

# 检查改动的 Go 文件是否已通过 gofmt/goimports，再执行 lint
make lint

# 查看发布前检查清单
make release-check
```

### 3. 提交和标签

```bash
# 提交变更
git add capi/main.go CHANGELOG.md
# 如有其他发布变更，逐项检查后暂存
git commit -m "Release v2.1.0"

# 创建标签
git tag v2.1.0

# 推送（会触发自动发布）
git push origin master v2.1.0
```

### 4. 本地测试发布（可选）

```bash
# 本地构建测试
make release VERSION=v2.1.0

# 查看生成的文件
ls -la dist/

# 在 macOS ARM64 上测试本机发布包，使用同版本仓库的示例源码
cd dist/ecapture_decryptor-v2.1.0-darwin-arm64
cc -o test ../../examples/c_demo/offline_decryption.c \
  -I./include ./lib/libecapture_decryptor.a -lpthread \
  -framework CoreFoundation -framework Security
cd ../..
```

Linux 上将两个 `-framework` 参数替换为 `-lresolv`。发布包必须在兼容的平台和架构上测试。

---

## 📋 常用命令

| 命令 | 说明 |
|------|------|
| `./scripts/version.sh show` | 显示当前版本 |
| `./scripts/version.sh bump patch` | 升级修订版本 (2.0.0 → 2.0.1) |
| `./scripts/version.sh bump minor` | 升级次版本 (2.0.0 → 2.1.0) |
| `./scripts/version.sh bump major` | 升级主版本 (2.0.0 → 3.0.0) |
| `./scripts/version.sh set v2.1.0` | 设置特定版本 |
| `make release VERSION=v2.1.0` | 构建发布包 |
| `make release-check` | 显示发布检查清单 |

`set` 接受可选的 `v` 前缀和 `X.Y.Z` 的预发布/构建元数据后缀。`bump` 对带后缀的当前版本报错；此时用 `set` 明确指定目标版本。版本字符串位于 `capi/main.go` 的 `eCapture Decryptor v...`。

---

## 🏷️ 版本号规则

```
vMAJOR.MINOR.PATCH

v2.1.0
│ │ │
│ │ └─ 修订版本 (bug 修复)
│ └─── 次版本 (新功能，向后兼容)
└───── 主版本 (破坏性变更)
```

### 何时升级版本

- **PATCH** (2.0.0 → 2.0.1): Bug 修复、文档更新、小改进
- **MINOR** (2.0.0 → 2.1.0): 新功能、性能改进、向后兼容
- **MAJOR** (2.0.0 → 3.0.0): API 破坏性变更、重大重构

---

## 📦 发布包结构

```
ecapture_decryptor-v2.1.0-darwin-arm64.tar.gz
├── lib/
│   ├── libecapture_decryptor.a      # 静态库
│   └── libecapture_decryptor.dylib  # 动态库
├── include/
│   └── libecapture_decryptor.h      # 头文件
├── LICENSE                          # 许可证
├── LICENSE-BINARY                   # 二进制许可
├── COPYRIGHT                        # 版权声明
├── README.md                        # 说明文档
└── SHA256SUMS                       # 校验和
```

标准包没有 `docs/` 或 `examples/`，示例源码在同版本仓库的 `examples/c_demo/`；Linux 动态库扩展名为 `.so`。

---

## 🌐 Release 工作流构建的平台

| 平台 | 标识 | 库文件扩展名 |
|------|------|-------------|
| macOS Apple Silicon | darwin-arm64 | .dylib |
| Linux x86_64 | linux-amd64 | .so |
| Linux ARM64 | linux-arm64 | .so |

`build-multiplatform.sh` 先构建本机平台，再用 Go 1.26 Docker 镜像构建 Linux amd64/arm64；Docker 需支持运行对应架构的容器。没有 Docker 时只构建本机平台；脚本不会构建另一种 macOS 架构，Release CI 也不包含 Darwin amd64。

---

## 🔄 自动化发布（推荐）

### 使用 GitHub Actions

```bash
# 1. 准备版本
./scripts/version.sh bump minor
vim CHANGELOG.md

# 2. 提交和推送标签
git add capi/main.go CHANGELOG.md
git commit -m "Release v2.1.0"
git tag v2.1.0
git push origin master v2.1.0

# 3. GitHub Actions 自动执行
#    - 多平台构建
#    - 创建 GitHub Release
#    - 上传发布包
#    - 生成 Release Notes
```

### 手动发布

```bash
# 1. 构建本机平台和两个 Linux Docker 目标
./scripts/build-multiplatform.sh v2.1.0

# 2. 使用 GitHub CLI 发布
gh release create v2.1.0 \
  --title "ecapture_decryptor v2.1.0" \
  --notes-file RELEASE_NOTES.md \
  dist/ecapture_decryptor-v2.1.0-*.tar.gz \
  dist/ecapture_decryptor-v2.1.0-*.tar.gz.sha256
```

自动发布与手动创建 Release 二选一，避免重复创建同一版本。工作流只由标签推送触发；`make release-check` 只显示清单，不执行验证。

---

## ✅ 发布前检查清单

- [ ] 代码已合并到 master 分支
- [ ] 更新版本号（使用 version.sh）
- [ ] 更新 CHANGELOG.md
- [ ] 所有测试通过 (`CGO_ENABLED=1 go test -race ./...`)
- [ ] 改动的 Go 文件通过 gofmt 和 goimports 检查
- [ ] 静态检查通过 (`make lint`)
- [ ] 许可证文件最新
- [ ] 文档已更新
- [ ] 本地测试发布包
- [ ] 创建 Git 标签
- [ ] 推送标签到 GitHub

---

## 🆘 常见问题

### Q: 如何回滚版本？

```bash
# 删除本地标签
git tag -d v2.1.0

# 删除远程标签
git push origin :refs/tags/v2.1.0

# 恢复版本号
./scripts/version.sh set v2.0.0
```

### Q: 发布失败怎么办？

```bash
# 清理并重试
make clean
rm -rf dist/
./scripts/release.sh v2.1.0
```

### Q: 如何发布预发布版本？

```bash
# 使用预发布标签
./scripts/version.sh set v2.1.0-beta.1
vim CHANGELOG.md
git add capi/main.go CHANGELOG.md
git commit -m "Release v2.1.0-beta.1"
git tag v2.1.0-beta.1
git push origin master v2.1.0-beta.1

# 等待标签工作流完成后，显式标记为 Pre-release
gh release edit v2.1.0-beta.1 --prerelease
```

Release 工作流固定 `prerelease: false`，不会按标签后缀自动标记预发布。

### Q: 如何只发布特定平台？

```bash
# 仅构建当前主机平台，不需要修改脚本
./scripts/release.sh v2.1.0
```

如需 CGO 交叉编译，必须同时设置目标 `GOOS`/`GOARCH` 和匹配的 C 工具链；仅设置平台变量不能保证可构建。

---

## 📞 获取帮助

- 📖 完整文档: [RELEASE_GUIDE.md](RELEASE_GUIDE.md)
- 🐛 报告问题: https://github.com/gojue/ecapture_decryptor/issues
- ✉️ 联系作者: cfc4n.cs@gmail.com

---

**最后更新**: November 7, 2026

