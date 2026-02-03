# OpenSSL 构建与测试示例

本文档给出一套最小且可重复的流程，用 OpenSSL 作为 TLS 实现来构建
libwebsockets，并运行 CTest 测试。

参考文档：
- READMEs/README.build.md
- READMEs/README.ctest.md

## 前置条件

- CMake (版本需足够新以支持 CTest)
- 可用的 OpenSSL
- 基础构建工具 (make, 编译器等)

如果使用的是非系统自带 OpenSSL，请显式指定 root 和 include/lib 路径。

## 配置并构建 (out-of-source)

在仓库根目录执行：

```bash
mkdir -p build
cd build
cmake .. -DLWS_WITH_MINIMAL_EXAMPLES=1
make -j$(sysctl -n hw.ncpu)
```

说明：
- `-DLWS_WITH_MINIMAL_EXAMPLES=1` 是标准 CTest 的必要条件
- Debug 构建：`cmake .. -DCMAKE_BUILD_TYPE=DEBUG`

### 使用自定义 OpenSSL (示例)

```bash
cmake .. \
  -DLWS_WITH_MINIMAL_EXAMPLES=1 \
  -DOPENSSL_ROOT_DIR=/usr/local/ssl \
  -DCMAKE_INCLUDE_DIRECTORIES_PROJECT_BEFORE=/usr/local/ssl \
  -DLWS_WITH_HTTP2=1
```

如需直接指定头文件和库：

```bash
cmake .. \
  -DLWS_WITH_MINIMAL_EXAMPLES=1 \
  -DLWS_WITH_HTTP2=1 \
  -DLWS_OPENSSL_INCLUDE_DIRS=/usr/local/include/openssl \
  -DLWS_OPENSSL_LIBRARIES="/usr/local/lib64/libssl.so;/usr/local/lib64/libcrypto.so"
```

## 安装到无特权 DESTDIR

CTest 需要 side-install，避免使用系统已安装的版本：

```bash
rm -rf ../destdir
make -j$(sysctl -n hw.ncpu) DESTDIR=../destdir install
```

## 运行测试 (CTest)

在 `build` 目录中执行：

```bash
LD_LIBRARY_PATH=../destdir/usr/local/share/libwebsockets-test-server/plugins \
ctest -j2 --output-on-failure
```

常用命令：

```bash
ctest -N
ctest -R "<test-name-or-regex>" --output-on-failure
```

无外网环境：

```bash
cmake .. -DLWS_WITH_MINIMAL_EXAMPLES=1 -DLWS_CTEST_INTERNET_AVAILABLE=0
```

## 常见问题

- 如果 CMake 选项看起来没生效，删除 `build/CMakeCache.txt` 或使用全新 build 目录。
- 确保 CTest 运行的是 `DESTDIR` 里的产物，而不是系统安装版本。

## 脚本使用方法

仓库根目录提供两个脚本：`build.sh` 和 `run-tests.sh`。

### build.sh

用途：清理并重新配置/编译（固定使用 `build/` 目录）。

```bash
bash build.sh
bash build.sh debug
bash build.sh openssl
bash build.sh debug mbedtls
```

说明：
- `debug` 等价于 `-DCMAKE_BUILD_TYPE=DEBUG`
- TLS 可选：`openssl`(默认) / `mbedtls` / `wolfssl` / `libressl` / `boringssl` / `awslc`

### run-tests.sh

用途：运行测试（默认不构建；需要构建时使用 `--build`）。

```bash
bash run-tests.sh
bash run-tests.sh --build
bash run-tests.sh debug --build
bash run-tests.sh mbedtls --no-internet --build
bash run-tests.sh -r ss-tf
```

常用选项：
- `--build`：先清理 `build/` 再重新配置/编译
- `--no-internet` / `--internet`：关闭/开启依赖外网的测试
- `-r <name>`：只运行某个测试（等价 `ctest -R`）
