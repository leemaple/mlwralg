# 60 组参数批量测试

本批次固定 security_bits=128、l=2，遍历 k∈{2,3}、N∈{4096,8192,16384}、depth∈{1,...,10}，共 2×3×10=60 个不同组合。每组均独立调用 OpenFHE 生成参数，实际尝试，保留成功和拒绝记录。

其余参数使用 configs/default.conf：slots=8、scale_bits=50、first_mod_bits=60、initial_scale_bits=0、precision_bits=20、message_bound=2、smudge_bound=0、rotation_steps=1、message_seed=20261013。每组正确性使用 3 把新密钥，每把 3 类消息；计时每项预热 2 次、采样 15 次。OpenFHE 1.6.1、单 digit HYBRID、FLEXIBLEAUTOEXT 和 128 classic RLWE 参数表保持原配置。

## 不用本地环境也可以运行

打开仓库 Actions，选择 **MLWR 60 parameter combinations**，点击 **Run workflow**。不需要逐个填 60 次参数。运行完成后下载 **parameter-grid-linux**，解压，打开 grid-60/report.html。workflow 绿色表示 60 组完整执行、记录并复核，不代表所有组合都被接受；查看报告中“通过”和“安全参数检查拒绝”的计数。

本地已完成编译时，在项目根目录执行：

```sh
python3 scripts/run_parameter_grid.py build/evidence/grid-60 build/mlwr_experiment
python3 scripts/verify_parameter_grid.py build/evidence/grid-60
```

输出目录必须是新目录或空目录，避免旧结果混入。再次运行可改用 grid-60-repeat。采样数量可用 --samples、--warmups、--key-trials 修改，正式本批次保持默认。测量按组串行执行；请避免同机同时运行其他高负载测试。

## 实际验证什么

1. **参数能否生成。** 检查给定 N 是否通过当前 OpenFHE 128 参数表。失败时保存原始错误和所需 N；不修改 N、不降低模数、不禁用安全检查。
2. **代码正确性。** 原有加解密、张量积恒等式、重线性化/重缩放系数界及乘法输出检查；另外实际运行 depth 层连续平方，每层执行乘法三步骤，解密后与明文 x^(2^层数) 比较。深度电路输入幅度≤min(1,message_bound)，包含实数、单位圆复数和随机消息，控制数值增长且包含不会因多层平方迅速趋零的输入。最终值和每一层都需满足最大复数绝对误差≤2^-20；同时保留实际误差、有效位数和严格 1/Δ 比较。
3. **时间。** 先通过所有正确性检查，再计时 15 项：普通密钥、重线性化密钥、旋转密钥、编码、加密、原始解密、初始准备、加法、旋转、乘法后解密、张量积、重线性化、重缩放、一次乘法总计、完整深度电路。前三个乘法阶段来自同一调用，可加总。完整深度电路以准备后的密文为输入，每层乘法及重缩放都包含在内；最终解密比较在计时区间之外。完整电路计时单独报告，不与一次乘法时间混淆。

深度电路是明确规定的测试负载，不代表任意同深度电路。security_bits=128 仍只是 OpenFHE 参数表标签，不能替代此 MLWR 研究构造的安全证明。当前单 digit HYBRID 会把辅助模数计入 OpenFHE 安全检查；因此维度不足时会在加密前拒绝。

## 打开哪些文件

| 文件 | 内容 |
|---|---|
| report.html | 可离线打开的 60 行结果报告，链接每组配置和证据 |
| summary.csv | 每组一行，参数、状态、误差和 15 项平均耗时；拒绝组测量留空 |
| timings.csv | 每个成功组每项一行，均值、中位数、标准差、P95 和样本数 |
| summary.json | 完整结果索引、源码指纹、环境及逐文件哈希 |
| cases/l2-k2-N16384-d01/requested.conf | 单组全部 17 项配置，可独立重跑 |
| cases/.../preflight.log | OpenFHE 原始拒绝原因；建议 N 仅是诊断，不会替换请求 N |
| cases/.../experiment.json | 成功组原始精度、逐层观测、真实模数、环境和时间样本 |
| cases/.../depth-correctness.csv、depth-slots.csv | 逐层最大误差及各槽明文、解密值和误差 |
| cases/.../timing-samples.csv | 每项 15 次未经汇总的毫秒观测 |

核对两环境结果时分别保留目录：

```sh
python3 scripts/verify_parameter_grid.py path/to/mac-grid path/to/linux-grid
```

验证器检查全部 60 个唯一组合、原始拒绝依据、每组文件哈希、误差/计时独立复算、连续平方的明文期望值，以及两环境的实现、参数和全部模数一致性。两机时间分别报告，不混合求平均。

## 代码改在哪里

- src/profile.cpp、src/options.cpp：深度上限扩展到 10，保留安全表检查。
- apps/mlwr_experiment.cpp：DepthInput、DepthCorrectness 和 depth_square_circuit；在原有三阶段实现上执行实际多层电路。schema_version 升为 3，大整数模数对数避免 double 溢出。
- scripts/run_experiment.py、verify_experiment.py：导出和独立复算逐层观测，保持旧版报告验证兼容。
- scripts/run_parameter_grid.py、verify_parameter_grid.py：遍历、错误分类、原始证据及完整覆盖复核。
- .github/workflows/parameter-grid.yml：GitHub 网页一键执行本批次。
