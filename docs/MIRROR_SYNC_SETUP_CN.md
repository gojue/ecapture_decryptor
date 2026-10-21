# Release 同步到镜像仓库功能说明

## 功能概述

在 `.github/workflows/release.yml` 中新增了 `sync-to-mirror` 任务，可以在主仓库发布 release 后，自动将产物同步到另一个组织下的镜像仓库。

## 新增的工作流程

1. **build-release**: 构建各平台的产物
2. **create-release**: 在主仓库创建 release
3. **sync-to-mirror** (新增): 将产物同步到镜像仓库
   - 仅上传构建产物（*.tar.gz 及其校验和文件）
   - 不包含源代码
   - 自动创建或更新镜像仓库的 release

## 配置方法

### 步骤 1: 创建 GitHub Personal Access Token (PAT)

1. 进入 GitHub Settings → Developer settings → Personal access tokens → Tokens (classic)
2. 点击 "Generate new token (classic)"
3. 选择权限范围: `repo` (完全控制)
4. 生成并复制 token

### 步骤 2: 在主仓库添加 Secret

在 **主仓库** (gojue/ecapture_decryptor):

1. Settings → Secrets and variables → Actions
2. 新建 Secret:
   - Name: `MIRROR_REPO_TOKEN`
   - Value: 粘贴刚创建的 PAT

### 步骤 3: 配置镜像仓库地址

在 **主仓库** (gojue/ecapture_decryptor):

1. Settings → Secrets and variables → Actions → Variables 标签
2. 新建 Variable:
   - Name: `MIRROR_REPO`
   - Value: 目标仓库地址，格式为 `owner/repo`
   - 例如: `another-org/ecapture_decryptor_releases`

### 步骤 4: 准备镜像仓库

在 **镜像仓库** (目标仓库):

1. 创建仓库（如果还不存在）
2. 确保 PAT 的所有者对该仓库有写入权限
3. 仓库可以是空的，release 会自动创建

## 工作原理

当你推送一个 tag（例如 `v1.0.0`）时：

```bash
git tag v1.0.0
git push origin v1.0.0
```

工作流会自动：
1. 构建所有平台的产物
2. 在主仓库创建 release
3. **自动将产物同步到镜像仓库**（新功能）

## 同步的内容

仅同步以下文件：
- `ecapture_decryptor-${VERSION}-darwin-amd64.tar.gz`
- `ecapture_decryptor-${VERSION}-darwin-amd64.tar.gz.sha256`
- `ecapture_decryptor-${VERSION}-darwin-arm64.tar.gz`
- `ecapture_decryptor-${VERSION}-darwin-arm64.tar.gz.sha256`
- `ecapture_decryptor-${VERSION}-linux-amd64.tar.gz`
- `ecapture_decryptor-${VERSION}-linux-amd64.tar.gz.sha256`
- `ecapture_decryptor-${VERSION}-linux-arm64.tar.gz`
- `ecapture_decryptor-${VERSION}-linux-arm64.tar.gz.sha256`

## 禁用同步功能

如需禁用同步功能：

1. 删除或清空 `MIRROR_REPO` 变量
2. 或者删除 `MIRROR_REPO_TOKEN` secret

同步任务会自动跳过（通过 `if: vars.MIRROR_REPO != ''` 条件判断）。

## 测试配置

```bash
# 创建测试 tag
git tag v0.0.1-test
git push origin v0.0.1-test

# 在 Actions 标签页查看工作流执行情况
# 验证两个仓库都有 release
```

## 示例配置

假设要同步到 `gojue/ecapture_decryptor` 仓库：

**Repository Variables:**
```
MIRROR_REPO = gojue/ecapture_decryptor
```

**Repository Secrets:**
```
MIRROR_REPO_TOKEN = ghp_xxxxxxxxxxxxxxxxxxxx
```

发布 `v1.2.3` 后，产物会出现在：
- 主仓库: `https://github.com/gojue/ecapture_decryptor/releases/tag/v1.2.3`
- 镜像仓库: `https://github.com/gojue/ecapture_decryptor/releases/tag/v1.2.3`

## 更多详情

参见英文文档: [docs/MIRROR_SYNC_SETUP.md](./MIRROR_SYNC_SETUP.md)

