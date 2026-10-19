# 根据 10 月 19 日会议新增的低模数版本

## 目标与状态

本轮把“降低模数后再尝试小 N”作为实现和实验任务。固定安全参数表 128、l=2，覆盖 k=2/3、N=4096/8192/16384、深度 1–10。旧版 ab5224c 的原始 60 组结果与交付包保留；新增模式用 compact=1 明确选择，不覆盖旧版算法或历史数据。

参考论文是 Cheon、Cho、Kim、Stehlé 的 **Homomorphic Multiple Precision Multiplication for CKKS and Reduced Modulus Consumption**，IACR 2023/1788，CCS 2023：[原始论文入口](https://eprint.iacr.org/2023/1788)。核对了本地同一 PDF 的第 6–8 页、论文的定义 3.3、4.1、4.3、4.5 及 4.7；其 SHA-256 为 61d9b948b17b6a624d3bf3372462555288308011226d2893e9e6bc3d6d197eac。

本地已有实现位于 20231788-openfhe-precision116-eight-square-20260907，另有 parameter-atlas-20260908 的参数核对资料。本轮阅读了高低表示、Relin2、RS2 及精确尺度递推代码；没有把它的 N=32768、h128、HEStd_NotSet 或已调整过的高精度实验参数当作本项目的 128 位认证。也没有迁入其客户端/上下文对象或替换当前固定 OpenFHE 1.6.1 依赖。

## 具体改了什么

标准模式仍采用原来的尺度、单 digit HYBRID 和普通乘法。compact 模式新增两项配合使用的改动：

1. **高低两份密文表示。** 按论文定义实现 DCP、RCB、Tensor2、Relin2、RS2。一次乘法的逻辑尺度除以 d×q_l，其中只有 q_l 在每层被消耗，避免普通乘法把同样的精度全部放在一个大的重缩放素数上。
2. **分解式密钥转换与小 P。** 将居中系数按平衡 B 进制分解，对每位的评估密钥做乘加，然后除去小辅助模数 P。评估密钥首分量嵌入 P×B^r×s_i×s_j。它使用本项目现有的独立取整源 W 生成行，并由本项目的 RNS 运算执行；不是调用 OpenFHE 原生 BV（原生路径按 CRT 塔分解），也不是直接把单 digit 改成任意 d_num 后沿用原公式。旋转默认用 14 位分解，可由 rotation_gadget_bits 修改，其实际参数和误差也单独检查。

纯 BV 的早期原型在旋转计时校验中失败，因此加入小 P 控制转换误差。该原型保留为失败记录，不纳入成功数据。

## 运算及尺度关系

对主模数 dQ 上的普通密文，每个系数做精确居中欧几里得分解：

- DCP(c)=(H,L)，H=round(c/d) mod Q，L=c−dH mod Q。
- RCB(H,L)=dH+L。重组后的逻辑尺度仍是原输入 Δ，而不是 Δ/d。
- Tensor2 的高项为 Tensor(H1,H2)，低项为 Tensor(H1,L2)+Tensor(L1,H2)，省略 L1L2。重组逻辑尺度成为 Δ1Δ2/d。
- Relin2 先将高项乘 d 并精确提升至 dQ，再重线性化和 DCP，将所得余数与重线性化低项合并。乘 d 的进位通过完整 CRT 整数映射保留。
- RS2 的 H'=RS(H)，C'=RS(dH+L)，L'=C'−dH'，因此 RCB(RS2)=RS(RCB)；只消耗同一个 q_l。逻辑尺度成为 Δ1Δ2/(d q_l)。

保留本项目的相位 c0−Σcj sj，二次项为正号。论文普通 Tensor 显示式和定理 4.8 的归一化因子存在已记录的局部不一致，本实现按上述自洽操作定义和尺度递推核对，未照抄缺少 d 的显示式。

## 怎样选参数、怎样核验 128 标签

每个 N 有一份配置，包含所有请求值，可自行修改：

| 文件 | N | 缩放素数目标位数 | 首素数目标位数 | d 目标位数 | 公开扩展/辅助素数目标位数 |
|---|---:|---:|---:|---:|---:|
| configs/compact/n4096.conf | 4096 | 28 | 48 | 17 | 16 |
| configs/compact/n8192.conf | 8192 | 32 | 54 | 18 | 17 |
| configs/compact/n16384.conf | 16384 | 34 | 56 | 20 | 20 |

初始 Δ 默认为实际 d 乘实际最后一个 q_mult；素数实际值逐项输出，不能以 2 的目标位数次方替代。低位 NTT 素数的数量有限；某些位数组合可能没有足够的不同素数，生成失败必须显示出来。

编码上下文保持 OpenFHE 的 HEStd_128_classic 检查；额外手动核验完整主模数 Q_full×P 与公钥模数 T 中较大的实际整数位数。4096、8192、16384 的当前 classic/ternary 表上限分别为 109、218、438 bits。源 W 只用于私有取整生成，但其实际值仍记录。此检查比只检查去掉 d 后的链更完整；它仍然不构成本修订 MLWR 构造的安全性证明。

此前尝试过 N8192、mult27/first49/d18 的 5 层候选。它的公开模数检查通过，但一次原型执行的第 5 层误差为 1.5180771454862349e-6，超过 2^-20；保留该失败日志。初次完整矩阵的 N16384/scale32 配置在深层最低层旋转及平方未达到 20 位门槛；失败证据保留。逐层记录显示省略的低项乘积贡献随电路层数增长，因此将 N16384 的 scale_bits 增至 34，保持 d、小 P 和验收门槛不变，并重新执行完整矩阵。增加的每层 2 位仍计入公开模数预算。较深组合仍按实际安全及数值结果分类，不保证所有 60 组都能成功。

## 怎么运行

标准模式仍用 configs/default.conf。低模数模式在项目根目录编译新版本一次后运行：

```sh
./build/mlwr_experiment --config configs/compact/n8192.conf --depth 4 --k 3 --print-parameters
python3 scripts/run_experiment.py build/evidence/my-compact build/mlwr_experiment \
  --config configs/compact/n8192.conf --depth 4 --k 3
python3 scripts/verify_experiment.py build/evidence/my-compact/experiment.json
```

配置的 compact=1 选择新增模式；rotation_gadget_bits 控制旋转密钥分解位数，默认 14；divisor_bits、gadget_bits、public_extra_bits 分别控制分解素数、平衡进制位数和公开扩展/小辅助素数位数。其余 l/k、深度、槽数、初始尺度、目标精度、消息幅度、解密噪声、旋转和测量选项继续生效。修改参数后仍须重新过安全和数值门槛。mlwr_demo 仅供标准模式；低模数用 mlwr_experiment。

没有本地构建环境时，GitHub Actions 选择 **MLWR compact pair 60 combinations** → Run workflow。工作流按 6 个 k/N 组合分组，合并时必须取得全部 60 个唯一组合且源码身份相同；缺组不能生成完整报告。最终下载 compact-grid-linux-complete，解压后打开 report.html。

本轮全组合筛选每项预热 1 次、计时 3 次，正确性每组使用 3 把独立新密钥，每把测试实数、单位圆复数及随机输入。计时保留全部样本、均值、中位数、标准差和 P95；这是本轮实际样本数，不继承论文或旧批次 15 次计时的统计范围。不同 GitHub runner 的 CPU/可执行文件身份保留在每组原始数据，耗时属于各机观测，不据此宣称算法加速倍数。

## 正确性和实际环绕检查

仍采用已确认的最大复数绝对误差 ≤2^-20，不改变门槛。每层同时报告实际误差、有效位数及严格 1/Δ。执行 depth 层连续平方并比较独立明文 x^(2^层数)，覆盖全部 8 个槽；深度电路使用幅度≤1 的实数、单位圆复数、随机输入，普通一次乘法继续使用原 message_bound=2 的输入族。

检查 DCP/RCB 和 RS2/RCB 的逐分量恒等式，并核对精确张量恒等式：d×phase(RCB(Tensor2))=phase(RCB(A))phase(RCB(B))−phase(LA)phase(LB) mod Q。

最后一层不能自动套用论文要求“除 d 前整个乘积不环绕”的充分条件。本轮直接检查实际所需的 d×H1H2+H1L2+L1H2：先用系数范数的卷积界；若该界不足，就在更大 RNS 基上精确重放该高低交叉和，并先证明较大基也不会环绕。实际交叉和须在当前 Q/2 内。每层的界、实际/有界范数、低项省略贡献和模数阈值写入 headroom_checks，由 Python 验证器复核记录。每个输入及输出 Pair 还检查 d×phase(H)+phase(L)=phase(RCB) 在整数多项式中完全相等。高、低两次密钥转换的相位误差分别记录；每条深度电路在最低层还单独检查旋转。

这些是本轮明确输入、密钥样本和电路上的验证，不是任意输入、所有随机密钥、所有同深度电路或完整安全性的证明。中间解密只发生在测试客户端，计算端的乘法、旋转和加法不接收秘密。

## 直接看代码

- src/compact.cpp、include/mlwr/compact.hpp：新增的高低密文、分解式转换、旋转。
- src/profile.cpp：实际素数、小 P、完整公开模数核验。
- apps/compact_experiment.cpp：正确性、实际交叉和环绕见证、逐层记录、15 项计时。
- configs/compact/：各 N 的显式配置。
- tests/compact_checks.cpp、tests/test_compact_cli.py：恒等式、边界、上下文和形状错误检查。
- scripts/run_parameter_grid.py、merge_parameter_grid.py、verify_parameter_grid.py：分组执行、完整覆盖合并和原始证据复算。
- .github/workflows/compact-grid.yml：网页重跑入口。
