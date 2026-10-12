# MLWR 浮点型同态算法实现

本项目用于实现用户提供方案的 RNS 版本。模块参数按口述暂记为
`l = k = 2`，需用原方案核对；算法差异从式（2-1）开始。

**当前状态：已建立并验证 OpenFHE 对照环境，尚未实现 MLWR 算法。**
三级中原始方案仍等待本次登录验证码，未下载，也尚未核对公式。
本仓库中的 `openfhe_reference` 是标准 CKKS 对照程序，不能作为 MLWR 实现。

## 固定依赖与参数

- C++17、CMake、Ninja。
- [OpenFHE v1.6.1](https://github.com/openfheorg/openfhe-development/releases/tag/v1.6.1)，
  提交 `b59e1f291965f14fbee5172cd83a20f5b856204f`。
- `NATIVE_SIZE=64`，静态库，OpenMP 关闭。
- 对照工作负载指定 `multiplicativeDepth=3`、`batchSize=8`。
- 其余密码参数直接采用该版本 `CCParams<CryptoContextCKKSRNS>` 默认值，
  包括 60 位首模数、50 位缩放模数、`FLEXIBLEAUTOEXT`、`UNIFORM_TERNARY`、
  `HYBRID` 和 `HEStd_128_classic`；环维度由 OpenFHE 自动选择。
- 程序输出实际 RNS 素数链，JSON 中的素数使用字符串以保留整数精度。

OpenFHE 的 RLWE 参数表只作为对照参数的选择依据，不构成新 MLWR 方案的安全证明。
拿到原方案后还须明确其舍入模数、取整规则、密钥分布和正确性条件。

## 本地构建与验证

需要 Git、C++17 编译器、CMake 3.20 或更新版本、Ninja。

```sh
bash scripts/build_openfhe.sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DOpenFHE_DIR="$PWD/.deps/openfhe-install/lib/OpenFHE"
cmake --build build --parallel 4
ctest --test-dir build --output-on-failure
./build/openfhe_reference
```

`MLWR_BUILD_JOBS` 可控制依赖构建的并行度，默认 4。
对照程序检验包含负数、零和小数的加解密、加法、乘法与连续平方，
检查非有限值，并以最大绝对误差 `1e-6` 为失败阈值。
GitHub Actions 使用 Ubuntu 24.04，保存实际参数与误差报告。

## 待原始方案确认的工作

1. 下载最新导出，保存原文件和哈希，核对式（2-1）起的全部定义。
2. 确认 `l = k = 2` 及 RNS 舍入语义，记录公式与代码的对应关系。
3. 与网页版 ChatGPT Pro 复核平台和算法边界。
4. 实现密钥生成、加解密、同态运算及方案定义的其他步骤，
   用小参数精确算术验证，再与相同参数的 OpenFHE 对照。

原始文件、本地会话记录及构建依赖由 `.gitignore` 排除。
