# MLWR 浮点型同态算法实现

基于交底书的模块结构，默认 `l = k = 2`，支持运行时独立设置 `l、k`，独立实现 RNS 近似同态运算，使用
OpenFHE 1.6.1 的多项式、NTT、随机采样和编码基础设施。包含可运行示例、
整数参考测试、原式反例和 macOS / Linux 验证流程。

**交付的是修订研究版。原式不能直接成为正确、安全的加密方案。**
原重线性化符号错误，编码缺少浮点尺度，公钥／加密的扩模结构存在公开恢复攻击。
修订版更换取整源模数、显式管理尺度并修正符号；这些是明确的构造修改，
详见 [公式与修订说明](docs/algorithm.md)。原式问题保留为独立可运行反例。
修订版的密码安全性仍未证明；正确性测试通过不等于安全证明。

已实现 Setup、KeyGen、RelinGen、Encode/Decode、Encrypt/Decrypt、Add、
PlainMult、Mult、Rescale、KSGen/KeySwitch、RotateKeyGen/Rotate。
原文没有定义 Bootstrap，本项目实现有限深度运算，不声称具有自举能力。

## 构建和运行

需要 Git、C++17 编译器、CMake 3.20+、Ninja、Python 3。

```sh
bash scripts/build_openfhe.sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DOpenFHE_DIR="$PWD/.deps/openfhe-install/lib/OpenFHE"
cmake --build build --parallel 4
ctest --test-dir build --output-on-failure
python3 scripts/compare_parameters.py build/evidence/openfhe-reference.json build/evidence/mlwr.json
./build/mlwr_demo
```

`MLWR_BUILD_JOBS` 控制 OpenFHE 构建并行度，默认 4。首次构建下载固定依赖。
`mlwr_demo` 演示复数向量的加密、平方、重缩放、左移和解密，逐槽打印误差。
公共接口位于 [scheme.hpp](include/mlwr/scheme.hpp)。

会议要求的参数、逐槽正确性和分阶段计时见 [实验与代码导读](docs/experiment-guide.md)。
构建后执行 `python3 scripts/run_experiment.py build/evidence/experiment build/mlwr_experiment`，
即可生成 JSON、误差 CSV 和时间 CSV；先通过正确性检查，再进行 2 次预热与 15 次正式测量。
乘法接口已显式拆成 `Tensor`、`Relinearize`、`Rescale`，保留原 `Mult` 调用方式。

## 自己修改参数

配置入口：[configs/default.conf](configs/default.conf)；完整说明：[参数修改手册](docs/parameter-guide.md)。
先更新并编译本版本一次，此后修改配置无需重新编译。`l、k` 可独立取 1..8，
`N=0` 自动选择，也可显式给定满足 OpenFHE 参数表要求的 2 的幂。
还支持槽数、深度、模数位数、初始编码尺度、验收精度、输入幅度、解密噪声、旋转和测量参数。

```sh
cp configs/default.conf configs/my.conf
# 用文本编辑器修改 configs/my.conf，以下命令都在项目根目录执行。
./build/mlwr_experiment --config configs/my.conf --print-parameters
python3 scripts/run_experiment.py build/evidence/my-run build/mlwr_experiment --config configs/my.conf
python3 scripts/verify_experiment.py build/evidence/my-run/experiment.json
```

命令行可临时覆盖文件，例如 `--l 3 --k 1 --n 32768 --slots 16`。
输出的 `parameters.csv` 对照请求值与实际值，`resolved.conf` 可复用。
GitHub Actions 的手动运行入口支持在 `parameters` 字段粘贴配置内容，在 Linux 上运行并下载结果。
默认历史回归仍固定原参数；新增参数回归独立测试可变维度、环维度和配置错误。

## 与 OpenFHE 的参数关系

固定版本为 [v1.6.1 / b59e1f2](https://github.com/openfheorg/openfhe-development/tree/b59e1f291965f14fbee5172cd83a20f5b856204f)，
`NATIVE_SIZE=64`、`MATHBACKEND=4`、静态库、关闭 OpenMP 和 native optimization。
双方使用同一个参数生成函数：

| 配置 | 数值／来源 |
|---|---|
| 默认运算深度、槽数 | 3、8；另外测试满槽，可配置 |
| HYBRID 大 digit 数 | 显式设为 1，适配原文无 gadget 的整体密钥转换 |
| 编码数据类型 | 显式设为 COMPLEX，保留原文消息域的虚部 |
| 其他共有设置 | OpenFHE 默认：首模数 60 位、缩放模数 50 位、FLEXIBLEAUTOEXT、UNIFORM_TERNARY、HEStd_128_classic |
| 实际主测试环维度 | 32768，由 OpenFHE 自动选择 |
| 主链、辅助链、单位根、初始编码尺度 | 直接复用 OpenFHE 生成结果；JSON 逐项核对 |
| 模块维度、新增源模数和公钥模数 | MLWR 研究构造独有，单独记录 |

这是一套双方相同的 **OpenFHE 配置**，并非所有选项均取库默认值。
旧的仅 CKKS 默认对照保留在 Git 历史中；它的环维度不能替代当前配置。
RLWE 安全参数表不构成本修订方案的 MLWR 安全证明。

多项式乘法使用 RNS/NTT；非线性的跨模数取整、中心提升目前采用精确 CRT
重构与大整数计算。这是以正确性为先的实现，尚未优化为全流程无大整数的 RNS。

## 验证与使用范围

- 独立 Python 整数算术核验 RNS/NTT、跨基舍入、中心提升、旋转和边界值。
- 原式反例验证错误符号、无尺度编码和公开恢复问题。
- C++ 使用多组新鲜随机密钥，覆盖负数、零、小数、复数、加法、明密乘、
  密密乘、三层连续平方、正负旋转、末层换钥、满槽及补零。
- 检查相位误差界和错误上下文／密钥／层级／尺度／模数链等拒绝条件。
- 浮点测试阈值为最大绝对误差 `1e-6`；执行报告记录每项实际误差。

CTest 自动生成 `build/evidence/*.json`。GitHub Actions 使用 Ubuntu 24.04 / GCC 13，
上传报告、编译器信息和测试日志。平台路线与网页版 ChatGPT Pro 协商后确定：
macOS arm64 开发、Linux x86_64 复现；本阶段不依赖 Windows 或 GPU。

默认输入的公开幅度上限为 `|z_i| <= 2`；其他范围通过 `Encode` 显式声明。
层级与尺度必须匹配，乘法后由调用者显式重缩放；本浮点配置拒绝小于 `2^40` 的尺度。
默认 `Decrypt` 不加噪，用于可信本地正确性实验；可传入均匀整数噪声上限测试
原文的 flooding 步骤，但没有得到满足其 IND-CPA^D 声明的参数证明。
接口不是经过审计的生产加密服务；目前无序列化、跨进程密钥管理或常数时间保证。

原始文件已保存在本地工作目录，原文件、会话记录和构建依赖均由 `.gitignore` 排除。
