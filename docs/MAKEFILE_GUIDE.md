# Makefile 使用快速参考

本项目的 Makefile 已重构为分层结构，职责清晰分离。

## 根目录 Makefile

**职责**: 库构建和项目级测试

### 常用命令

```bash
# 构建静态库（默认）
make
make build-static

# 构建动态库
make build-shared

# 构建所有库
make build

# 运行单元测试
make test

# 清理库文件
make clean

# 代码格式化
make fmt

# 静态检查
make lint

# 帮助信息
make help
```

### 输出产物

- `lib/libecapture_decryptor.a` - 静态库
- `lib/libecapture_decryptor.so` - 动态库（如果构建）
- `include/libecapture_decryptor.h` - C 头文件

---

## examples/Makefile

**职责**: 管理所有示例程序

### 常用命令

```bash
cd examples

# 构建所有 demo
make build

# 测试所有 demo
make test

# 清理所有 demo
make clean

# 单独构建某个 demo
make build-go-demo
make build-c-demo
make build-go-static-demo

# 单独测试某个 demo
make test-go-demo
make test-c-demo
make test-go-static-demo

# 帮助信息
make help
```

### 输出产物

所有 demo 的二进制文件都输出到 `bin/` 目录：
- `bin/ecapture_decryptor` - Go demo
- `bin/offline_decryption` - C demo
- `bin/live_capture_simple` - C demo
- `bin/stream_decryption` - C demo
- `bin/go_static_decryptor` - Go static demo

---

## 单个 Demo 目录

每个 demo 都可以独立构建和测试：

### Go Demo

```bash
cd examples/go_demo
make build
make test
make clean
```

### C Demo

```bash
cd examples/c_demo
make all        # 自动构建依赖库（如果需要）
make test
make clean
```

### Go Static Demo

```bash
cd examples/go_static_demo
make build
make test
make clean
```

---

## 常见工作流

### 1. 库开发者工作流

```bash
# 在根目录
make build-static   # 构建库
make test           # 运行单元测试
make fmt            # 格式化代码
make lint           # 静态检查
```

### 2. 示例程序开发者工作流

```bash
# 在 examples 目录
make build          # 构建所有 demo
make test           # 测试所有 demo
```

### 3. 单个 Demo 开发工作流

```bash
# 在具体 demo 目录
cd examples/go_demo
make build
make test
```

### 4. 完整测试工作流

```bash
# 根目录 - 测试库
make test

# examples 目录 - 测试所有 demo
cd examples && make test
```

---

## 目录结构

```
ecapture_decryptor/
├── Makefile                    # 库构建
├── lib/                        # 库输出
├── include/                    # 头文件输出
├── bin/                        # Demo 二进制输出
└── examples/
    ├── Makefile                # Demo 总控
    ├── go_demo/
    │   └── Makefile            # Go demo
    ├── c_demo/
    │   └── Makefile            # C demo
    └── go_static_demo/
        └── Makefile            # Go static demo
```

---

## 优势

1. **职责分离**: 库开发和示例程序分离
2. **独立构建**: 每个组件可以独立构建和测试
3. **清晰结构**: 降低复杂度，易于维护
4. **灵活使用**: 可以选择性构建需要的组件
5. **CI/CD 友好**: 支持分层测试

