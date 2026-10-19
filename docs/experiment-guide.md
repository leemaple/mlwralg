# 2026 年 10 月 13 日会议实验说明

本页记录 10 月 13 日默认实验口径。10 月 19 日起支持运行时配置，详见 [参数修改手册](parameter-guide.md)；本页的 2/2/32768、8 槽、三组密钥与 15 次采样为默认值。

实验输出固定分成三部分：1 参数，2 正确性，3 各阶段时间。另附代码导读，
让接收人在无法编译的环境中也能核对实现和结果。原始要求图片和会议文字保存在本地交付包，
不随代码仓库公开。

## 参数应当怎么看

`src/profile.cpp` 的 `OpenFheProfile` 生成共有 OpenFHE 配置。
`WriteProfileJson` 输出实际素数、单位根、环维度、深度和编码尺度。
主实验为 `l=k=2`、`N=32768`、8 个复数槽、乘法深度 3。
`HEStd_128_classic` 是共有参数的 RLWE 选择标签，不能据此认定修订 MLWR 方案获得了 128 位安全证明。

本项目的 P 是主密文模数，Q 是换钥辅助模数，T 是新增公钥模数，W 是独立取整源模数。
它们与 OpenFHE 文献中主模数 Q、辅助模数 P 的命名相反；论文中的 log q 必须注明指哪个模数。
实验报告同时列出每种模数的精确整数、素数分解、整数位长和 log2，避免混用。

## 正确性应当怎么看

第一条验证链为 `x -> Encode -> Encrypt -> Decrypt(含 Decode) -> x_hat`。
逐槽计算复数误差 `abs(x_hat[i] - x[i])`，取最大值。第二条链先分别加密 x、y，
归一化初始尺度，再执行 `Tensor -> Relinearize -> Rescale -> Decrypt`，
与独立的明文逐槽乘积 `x[i]*y[i]` 比较。测试输入均为二进制可精确表示的小数，
包含实数、复数、零、正负数及固定种子的公开随机消息；秘密和加密随机量不固定种子。
三个独立新密钥各测试三对消息，共九组；每组保留两条新鲜解密、两条准备后解密、
重缩放前后乘法及编码结果的八槽完整记录。

Δ 是编码尺度，log2 Δ 是尺度指数。有效精度位数用 `-log2(max_absolute_error)` 报告，
零误差时该字段为 null，表示超出本次浮点观测的分辨率。有效精度不等于尺度指数。
若相位系数噪声为 e，解码误差包含 `sigma(e)/Δ`、编码误差和浮点计算误差，
因此一般不能直接保证误差 ≤ 1/Δ。

会议未规定 δ 的具体数值。实验预先使用 `2^-20 = 9.5367431640625e-7` 作为工程验收阈值，
与此前 `1e-6` 接近且略严格。该阈值明确是沿用的实验目标，不能冒充会议指定值。
每条记录也输出 1/Δ、误差乘 Δ 以及“是否满足 1/Δ”，严格比较失败仍原样保留。
这些数据可用于判断更高精度的要求；不能只看到“通过”就推断达到 50 位精度。

除明文比较之外，还检查：张量相位恒等式、加密系数误差界、重线性化误差界、
重缩放相位误差界。具体界与原式反例见 `docs/algorithm.md`。

## 时间应当怎么看

`apps/mlwr_experiment.cpp` 的 `Correctness` 先全部通过，随后才进入 `Benchmark`。
使用 `steady_clock`，每项预热 2 次、正式记录 15 次；保留每次毫秒数，并给出均值、
中位数、样本标准差、最小值、最大值和最近秩 P95。计时单位为一次调用处理一个 8 槽向量，
不是单槽时间。每次检查输出都在计时区间外进行。

- KeyGen 包含秘密和公钥生成；重线性化密钥、旋转密钥生成单列。
- Encode 单列；Encrypt 的输入已经编码，计时包含新随机量采样。
- Decrypt 含相位计算与解码，分别报告新鲜密文和乘法结果密文。
- FLEXIBLEAUTOEXT 的初始准备重缩放单列，每个输入需要一次；不混入乘法第三阶段。
- 乘法在同一次调用中依次打四个时间戳，得到张量积、重线性化、重缩放及总时间。
  每次三个分项相加等于该次总时间；分项中位数之和不必等于总时间的中位数。
- Add 和向左旋转一个槽在准备后的 level 1 上测量；旋转密钥已提前生成。
- Setup 和主机编译耗时不属于这些在线操作时间。这里是进程内预热测量，未宣称冷启动表现。

不同机器的时间各自报告；不能把两台机器之间的时间比值写成算法加速比。
本轮没有同机 CKKS 性能基准，不能据此声称性能优于 CKKS。

## 从代码哪里开始看

| 要核对的内容 | 文件和函数 | 直接可见的行为 |
|---|---|---|
| 参数来源 | `src/profile.cpp` / `OpenFheProfile` | 共有配置的显式设置与默认项 |
| 模数与构造修订 | `src/scheme.cpp` / 构造函数、`MakeRow`、`KeyGen` | W 到 T 的取整，独立秘密、公钥生成 |
| 浮点编码与译码 | `Encode`、`Decode` | 尺度 Δ 以及 FFT 映射 |
| 加密 | `Encrypt` | 采样 r，计算公钥内积，T 到 P 取整并加消息 |
| 解密 | `Phase`、`Decrypt` | c0-c1*s0-c2*s1，再调用 Decode |
| 张量积 | `Tensor` | 3 个线性项、4 个二次项，尺度相乘 |
| 重线性化 | `Relinearize`、`SwitchProduct` | 二次项转回 3 分量，按正号加入 |
| 重缩放 | `Rescale` | 实际整体除模数塔并取整，同时更新尺度 |
| 加法与旋转 | `Add`、`Rotate` | 分量加法；环自同构后换钥 |
| 实际误差与计时 | `apps/mlwr_experiment.cpp` | 独立明文结果、逐槽记录、三个计时边界 |
| 历史回归与拒绝条件 | `tests/mlwr_checks.cpp` | 多层运算、原组合入口与拆分入口逐分量相等 |
| 结果再计算 | `scripts/verify_experiment.py` | 从原始槽值、样本重算误差、统计量及时间之和 |

`Mult(a,b,key)` 仍然等价于 `Relinearize(Tensor(a,b),key)`，调用者继续显式 Rescale。
此次拆分没有更改已交付修订算法的数学公式；新增的是可独立核对、计时的接口。
相对原始交底书的构造修订仍以 `docs/algorithm.md` 为准，不能与这次实验呈现改进混为一谈。

## 复现与证据文件

```sh
cmake --build build --parallel 4
ctest --test-dir build --output-on-failure
python3 scripts/run_experiment.py build/evidence/experiment build/mlwr_experiment --samples 15 --warmups 2
python3 scripts/verify_experiment.py build/evidence/experiment/experiment.json
```

输出 `experiment.json`（含机器、编译器和实现文件 SHA-256）、`correctness.csv`、
`slots.csv`、`timings.csv`、`timing-samples.csv`、`experiment.log`。
脚本先删除旧成功报告；失败时生成 `failure.json`，避免残留旧文件被误认作新结果。
两个环境报告可以同时传给核验脚本，检查实现身份、全部主辅和新增模数以及尺度一致。
CSV 含 UTF-8 BOM，可在 Windows Excel 中直接打开。离线阅读报告无需安装编译器。
