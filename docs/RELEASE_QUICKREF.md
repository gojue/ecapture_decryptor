# Quick Release Reference - 快速发布参考

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
# 运行测试
make test

# 代码格式化和检查
make fmt
make lint

# 查看发布前检查清单
make release-check
```

### 3. 提交和标签

```bash
# 提交变更
git add .
git commit -m "Release v2.1.0"

# 创建标签
git tag v2.1.0

# 推送（会触发自动发布）
git push origin main --tags
```

### 4. 本地测试发布（可选）

```bash
# 本地构建测试
make release VERSION=v2.1.0

# 查看生成的文件
ls -la dist/

# 测试发布包
cd dist/ecapture_decryptor-v2.1.0-*/
gcc -o test docs/examples/offline_decryption.c -I./include -L./lib -lecapture_decryptor
```

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
├── docs/examples/                   # 示例代码
├── LICENSE                          # 许可证
├── LICENSE-BINARY                   # 二进制许可
├── COPYRIGHT                        # 版权声明
├── README.md                        # 说明文档
└── SHA256SUMS                       # 校验和
```

---

## 🌐 支持的平台

| 平台 | 标识 | 库文件扩展名 |
|------|------|-------------|
| macOS Intel | darwin-amd64 | .dylib |
| macOS Apple Silicon | darwin-arm64 | .dylib |
| Linux x86_64 | linux-amd64 | .so |
| Linux ARM64 | linux-arm64 | .so |

---

## 🔄 自动化发布（推荐）

### 使用 GitHub Actions

```bash
# 1. 准备版本
./scripts/version.sh bump minor
vim CHANGELOG.md

# 2. 提交和推送标签
git add .
git commit -m "Release v2.1.0"
git tag v2.1.0
git push origin main --tags

# 3. GitHub Actions 自动执行
#    - 多平台构建
#    - 创建 GitHub Release
#    - 上传发布包
#    - 生成 Release Notes
```

### 手动发布

```bash
# 1. 构建所有平台
./scripts/build-multiplatform.sh v2.1.0

# 2. 使用 GitHub CLI 发布
gh release create v2.1.0 \
  --title "ecapture_decryptor v2.1.0" \
  --notes-file RELEASE_NOTES.md \
  dist/ecapture_decryptor-v2.1.0-*.tar.gz
```

---

## ✅ 发布前检查清单

- [ ] 代码已合并到 main 分支
- [ ] 更新版本号（使用 version.sh）
- [ ] 更新 CHANGELOG.md
- [ ] 所有测试通过 (`make test`)
- [ ] 代码已格式化 (`make fmt`)
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
git tag v2.1.0-beta.1
git push origin v2.1.0-beta.1

# 在 GitHub Release 中标记为 Pre-release
```

### Q: 如何只发布特定平台？

```bash
# 修改 release.sh 或直接构建
make build-static
make build-shared

# 手动打包
cd dist
tar -czf ecapture_decryptor-v1.1.0-darwin-arm64.tar.gz ...
```

---

## 📞 获取帮助

- 📖 完整文档: [RELEASE_GUIDE.md](RELEASE_GUIDE.md)
- 🐛 报告问题: https://github.com/cfc4n/ecapture_decryptor/issues
- ✉️ 联系作者: cfc4n.cs@gmail.com

---

**最后更新**: January 5, 2026

