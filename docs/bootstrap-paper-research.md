# 四份自举论文与当前 MLWR 实现的兼容性核查

核查日期：2026-10-20。本文是实施依据与验收条件，不是已经完成自举或已经达到某个参数点的声明。依据为用户指定的四份英文原件、同目录保存的稀疏论文后续修订、作者代码以及固定 OpenFHE 1.6.1 源码；`reports/comparison.md` 只用于确认四份文件的身份。

本轮实施后的状态单独见 [40次乘法自举实测](bootstrap-results-20261020.md)和 [小参数实测](compact-results-20261020.md)。下文第5节保留原始研究路线；第8节更新已关闭的证据缺口。规划中的技术不能与已经完成的功能混为一谈。

## 1. 确认是哪四份

|编号|英文原件与作者|版本、原件页数|独立贡献|
|---|---|---|---|
|P01|Lianglin Yan, Pengfei Zeng, Heyang Cao, Peizhe Song, Mingsheng Wang, *Faster Bootstrapping for CKKS with Less Modulus Consumption*|作者完整版，2026-03-04 提交说明，51 页；ePrint 2025/1403|LCR、AKS 及组合，完整附录|
|P02|Jihwan Kim, Jung Hee Cheon, Yongdong Yeo, *OverModRaise: Reducing Modulus Consumption of CKKS Bootstrapping*|IACR Communications in Cryptology 2(3)，32 页；DOI 10.62056/a3n5qjp10|OverModRaise1、OverModRaise2、Tuple-CtS/StC|
|P03|Xiaopeng Zheng, *Faster CoeffToSlot and SlotToCoeff for Sparsely Packed Ciphertexts with Application to CKKS Bootstrapping*|用户原件 38 页；ePrint 2026/1023|重复稀疏槽布局下的单层 CtS/StC|
|P05|与 P01 同名、同作者|PKC 2026，LNCS 16554，出版页 335–366，PDF 32 页；DOI 10.1007/978-3-032-26740-5_11|P01 的正式发表版本，不是第四条独立算法|

原件链接：[P01](</Users/lifeng/Documents/徐博论文翻译及整理/sources/【非密】2-2-Faster Bootstrapping for CKKS with Less Modulus Comsumption.pdf>)、[P02](</Users/lifeng/Documents/徐博论文翻译及整理/sources/【非密】0-自举2-1-OverModRaise Reducing Modulus Consumption of CKKS bootstrapping.pdf>)、[P03](</Users/lifeng/Documents/徐博论文翻译及整理/sources/【非密】0-自举-2026-1023Faster CoeffToSlot and SlotToCoeff for Sparsely packed.pdf>)、[P05](</Users/lifeng/Documents/徐博论文翻译及整理/sources/【非密】2-2-PKC26-正式版Faster Bootstrapping for CKKS with Less Modulus Comsumption.pdf>)。下文页码均为 PDF 物理页；P05 的出版页码等于物理页加 334。

在线身份核对：[P01/P05 ePrint](https://eprint.iacr.org/2025/1403)、[P02 正式论文](https://cic.iacr.org/p/2/3/32)、[P03 ePrint](https://eprint.iacr.org/2026/1023)。P04/P06 的矩阵同态论文不在用户此次指定的四份内。

**P03 有必须保留的版本差别。** 本地用户原件 pp.23–27 用旧的稀疏/均匀密钥实验及范围概率设置；本地已有的 [40 页后续修订](</Users/lifeng/Documents/徐博论文翻译及整理/research/sources/p03_current_2026-09-22.pdf>) pp.23、26 改为 sparse-secret encapsulation，主密钥重量 192、临时密钥重量 32，自定义布局取 `K=24, degree=42, double_angle=3`，标准布局取 `16,32,3`。其目标是在文中的统计模型下全槽越界概率小于 `2^-128`。该概率、128 位攻击安全性、20 位数值精度是三个不同指标。后续修订不能无说明地冒充用户原件；其自举参数也不能替换当前 MLWR 的均匀三元密钥分布。

## 2. 对 N=8192 的直接判断

这些论文优化的是**已经存在的自举流程**，不会仅靠增加 `bootstrap=true` 就使当前四层 MLWR 链获得无限深度。自举本身也消耗模数；增加循环次数只能在每次自举确实恢复正数可用层数、且累计误差满足要求时扩大总电路深度。P01/P05 表 3（p.24）测试 `N=65536`；P02 表 3（p.21）含 `N=32768/65536`；P03 两版本的主要实验均是 `N=65536`。这些数据没有直接证明 `N=8192`、当前 20 位最大误差要求、当前 MLWR 构造同时可行。

当前代码 `src/profile.cpp::CompactProfile` 用 BV 编码上下文，另检查完整 `Q_full×P` 与公钥模数 `T` 的最大实际位数；当前 ternary/classic128 表在 N=8192 的上限是 218 位。[当前 compact 核查](compact-research.md)和 [profile.cpp](../src/profile.cpp)记录了该约束。新自举必须把所有公开的自举密钥、桥接密钥及临时模数纳入同一核查，不能只核查原来的四层应用链。

官方 OpenFHE 1.6.1 的 `EvalBootstrapSetup`、`EvalBootstrapKeyGen`、`EvalBootstrap` 明确要求 HYBRID；其参数生成检查实际 `Q×P`。当前 compact 对象不能直接传给该 API。官方小 N 自举示例使用 `HEStd_NotSet`，不能用于证明本项目的安全参数可行。[自举源码](https://github.com/openfheorg/openfhe-development/blob/v1.6.1/src/pke/lib/scheme/ckksrns/ckksrns-fhe.cpp)、[参数生成源码](https://github.com/openfheorg/openfhe-development/blob/v1.6.1/src/pke/lib/scheme/ckksrns/ckksrns-parametergeneration.cpp)、[官方示例](https://github.com/openfheorg/openfhe-development/blob/v1.6.1/src/pke/examples/simple-ckks-bootstrapping.cpp)。

**实施判据：** 对 N=8192 保留并实际测试候选点，输出安全预算拒绝、误差失败或通过；不能预先承诺支持，也不能据目前几个候选失败宣称数学上不可能。扩展 N=32768/65536 能提供可运行自举的参考点，但必须把其 N 与原 8192 结果分别显示。

## 3. 各论文具体能迁移什么

### 3.1 P01/P05：LCR 与 AKS

P01 p.13 定理 1、P05 p.13 定理 1 的 LCR 条件是对**固定整数代表元的未取模解密内积**满足 `||<ct,sk>||∞ < Q/2`。此时分量除以 q 并舍入可保留模数 Q。仅仅“解密后的明文很小”不够，因为普通密文的内积可能另外包含非零整数倍 Q。

ModRaise 的低模数代表元提供这个特殊状态。P01/P05 p.14 Remark 1 明确指出稀疏打包的 SubSum 含旋转/密钥切换，会破坏这一状态，因此原文 LCR 路线假定满槽。不能将现有 `Rescale2` 全部换成 LCR，不能在普通旋转后凭借模数尚有空间就执行 LCR。

AKS 把固定对角线明文乘法和缩放嵌入旋转评估密钥。**普通 AKS 仍降一层**；P01/P05 p.23 §5.1 的 LCR+AKS 才保层，且在该处采用 GHS 型切换，避免 hybrid CRT 分解重组的 `k₂Q` 经除 q 后留下 `k₂Q/q`。同页式 (5) 还要求嵌入常数/密钥乘积不绕回，以及 `q₀N/(4P)+q₀N||e_ks||∞/(2P)` 足够小。当前 MLWR 的小 P、平衡全局 gadget 切换不是原文的 GHS 证明对象，不能照搬结论。

可实施路线：建立满槽自举分支，在首次切换前记录精确代表元与公开上界；专门生成 LCR+AKS 密钥；只在首个 CtS 因子启用。MLWR 负相位和 k 个秘密分量要重新推导；若通过标准 RLWE 桥接在自举内部使用该算法，则应明确这是 RLWE 内核上的论文优化。P01 p.27/P05 p.27 支持将稀疏密钥的解封装并入 AKS，但这不是“稀疏数据布局”兼容性证明。

作者实现为 [Fainabi/Lattigo-LCR-AKS](https://github.com/Fainabi/Lattigo-LCR-AKS)，分支 `lcr`，Go/Lattigo。关键入口为 `GenAggregatedLevelConservedKeyNew`、`dftLevelConserved`、`MultiplyByDiagMatrixLevelConserved`。未发现作者提供 OpenFHE 1.6.1 的可直接应用补丁。它适合逐算子复现与对照，不是复制到本项目即可使用的适配层。

### 3.2 P02：OverModRaise1/2

P02 pp.9–10 的 OverModRaise1 先提升至 `Q_over > Q_max`，把第一次明文乘法和普通缩放移到首次旋转之前。按原文的最大公开模数模型，必须同时核查：

- 临时密文 `Q_over < P Q_max`；
- 首次切换 `P Q_over / Δ_CtS <= P Q_max`；
- 若取 `Q_over=Q_max Δ_CtS`，则还需 `1<Δ_CtS<P`。

其首层无法沿用原来依赖同一输入的 BSGS，需要不均衡矩阵分解。不能只是把参数链多加一个素数，却仍立即在过高模数上旋转。上述安全模型本身也不是对本项目 MLWR 的形式安全证明。

OverModRaise2（pp.12–15）额外除 `Δ_S`，CtS 后 InvRS 恢复，新增误差被放大为 `Δ_S e_RS`。增加各因子矩阵的编码精度来补偿后，其候选模数收益是 `log₂Δ_S − n_c` 位，不是免费增加任意层数。原文概率分析使用独立均匀舍入与正态近似，不能直接当成本构造的严格失败概率。

二者合用时，P02 p.20 Algorithm 1 的临时模数为 `Q_max Δ_CtS Δ_S`；需要检查乘积而不只是分别检查两个因子。把同一步的普通缩放再改为保层 LCR，可能令首次切换前的模数没有降回来。因此 LCR 与 OverModRaise 的一般兼容声明不等于收益可直接相加，必须明确哪一个独立因子在哪一步被消耗。

作者实现为 [aqua4689jh/OverModRaise](https://github.com/aqua4689jh/OverModRaise)，基于自有 EvalRound C++。P02 p.21 明确其基线未包括 BSGS、hybrid、double hoisting、SSE 等多项优化，且实验简化误差分布与参数说明不同。作者测试入口在 `proposal_main.cpp`，没有可直接应用到 OpenFHE 1.6.1 的补丁。当前项目更合适先加入可审计的候选规划与失败条件，避免把这个实验的加速倍数当成本实现实测。

### 3.3 P02：Tuple 线性变换与当前高低位表示

这是与现有 compact 算法最接近的迁移点。P02 p.28 Definition 6 给出 tuple plaintext×ciphertext，保留 HH、HL、LH，省略 LL；输出总除数为 `d q_l`。当前实现已经具有相同形式的双密文表示及带进位的 `Rescale2`，但尚没有因此自动获得完整 CtS/StC 或 EvalMod。

可增加独立的 tuple 明文乘法、线性变换与低位增长观测。省略项应按 `low_plain × phase(low_ct)/(d q_l)` 核验；验证应包含负系数、舍入边界、多个连续因子矩阵。P02 pp.16–18 的节省来自连续 `n_Lin` 次变换只分解一次、最后重组，收益因子为 `d^(n_Lin−1)`；对一个单层 sparse CtS 单独分解并立即重组，指数为零，没有该项模数收益。

原件存在不能静默照抄的公式不一致：p.9 Definition 3 低位输出的减项写了 `d RS(low)`，但保持重组恒等式需要 `d RS(high)`；p.29 Theorem 1 左侧目标写 `1/q_l`，同页正文及 p.28 Lemma 5 要求总因子 `1/(d q_l)`，且定理条件与证明相差 `+h`。当前 `src/compact.cpp::Rescale2` 已采用符合重组恒等式的高位减项。新实现应明确写出采用的代数定义并用精确整数测试，而不是宣称已经得到作者勘误确认。

### 3.4 P03：重复稀疏槽的单层 CtS/StC

P03 p.5 Theorem 1 要求 N 为 2 的幂、`n=2m | N`、`r=N/n>=4`，有效 m 个槽在完整 N/2 槽中重复 r 次。每个变换各消耗一层；当 `n<=r/2` 时一次明文乘法，否则是 `2n/r=8m²/N` 次。CtS 还需共轭。编码少量非零槽不等于满足重复布局，导入密文必须验证布局约定。

这是当前最接近 OpenFHE 的可执行迁移路线。对于 N=8192，槽数 m=64/128/256/512/1024 分别满足 r=64/32/16/8/4，理论明文乘法数为 4/16/64/256/1024（每个变换）。m=16/32 属于单乘法区间。**这些是代数操作计数，不是该 N 下自举安全性或20位精度通过结果。**

原件 pp.22–24 与修订 p.23 都要求检查所有辅助槽的 EvalMod 输入范围。在原文统计模型下，保守范围为 `K >= sqrt((h+1)/6 * ln(N/δ))`。h 必须对应 ModRaise 时实际使用的密钥分布，不是随便填的调参变量。修订在 N=65536、临时 h=32、δ=2^-128 时用 K=24，而不是标准布局的16；相应增加 Chebyshev 次数。真实编码还需测量理想矩阵中的零被近似编码后的误差，不能仅测前 m 槽而漏掉辅助槽越界。

## 4. 作者 OpenFHE 补丁的适配成本

作者仓库 [SlotToCoeff-and-CoeffToSlot](https://github.com/xiaopeng-stu/SlotToCoeff-and-CoeffToSlot) 当前读取的固定提交为 `abec1a68cc110a0afdb54fa2fed412a7b381a8e6`（2026-09-07）。[patch.py](https://github.com/xiaopeng-stu/SlotToCoeff-and-CoeffToSlot/blob/abec1a68cc110a0afdb54fa2fed412a7b381a8e6/patch.py) 有 3,931 行；[main.cpp](https://github.com/xiaopeng-stu/SlotToCoeff-and-CoeffToSlot/blob/abec1a68cc110a0afdb54fa2fed412a7b381a8e6/main.cpp) 有 4,974 行。README 推荐目标版本为 OpenFHE v1.5.1；其 CLI 默认安全档是128，但保留可选 NotSet，本项目应禁用该退路。

对照当前固定 1.6.1 源码，可以直接确认以下不兼容点：

|作者补丁假定|本项目依赖的实际结构|迁移要求|
|---|---|---|
|patch.py 3794–3799 查找旧的显式 PartialSum `for` 循环|`EvalBootstrap` 稀疏分支调用 `EvalPartialSumInPlace(raised, slots)`|显式接入新分支，不能运行旧字符串替换后当作成功|
|在旧 ModRaise 块中分割 SSE、计时和归一化|当前 `ModRaiseInPlace` 已封装相关流程|重新确认小系数状态在哪一步仍存在|
|替换原来的 `std::cerr`/`std::cout` 计时串|当前使用 `OPENFHE_DIAGNOSTIC_ERR`|重新布置不重叠的阶段计时|
|修改运行时 K、degree、预计算与深度的多个入口|当前范围归一化通过 `GetModRaiseOverflowBound` 等辅助函数进入矩阵|保证矩阵、EvalMod 系数、实际深度、SSE重量一起同步|

补丁的 stage0 是原生 OpenFHE，stage5 才是自定义 CtS+EvalMod+StC；stage1/2/3/4 是中间态，不能称完整自举。移植时建议提取自定义掩码/对角层/块部分和代码为明确模块，再挂到稀疏分支；不要带入诊断环境变量、计时归一化选项就默认称为生产接口。必须记录实际走过的实现分支。作者补丁的环境变量为进程全局，比较不同 K/degree 的上下文时尤其要防止串用。

## 5. 当前可实现的分阶段路线

1. **原生 OpenFHE 参考。** 用其正式 HYBRID 自举，自动选 N 或显式指定后保留128表检查；记录完整 Q/P、预算、剩余层、误差和分阶段时间。该结果只证明参考内核及测试环境工作，不能写成 MLWR 自举或四论文融合。
2. **公开密钥切换桥接。** 为当前 MLWR 建立同环、同根与精确共享基底的 MLWR→RLWE→MLWR 路径，然后在 RLWE 部分执行真实 `EvalBootstrap`。评估器只持评估键/公开数据；私钥仅用于离线生成键与独立验收。自举后继续做 MLWR 乘法并至少再完成第二次刷新，证明确实恢复计算能力。
3. **实际可兼容的 P03 内核。** 先在 RLWE 参考中移植 repeated-slot CtS/StC，比较同精度/同安全条件下的 {1,1}/{2,2}/{3,3} 与自定义路径；通过后再接桥接。新增 K/degree 不得只改显示值。该阶段才可声称实现了相应论文优化。
4. **P02 tuple 明文线性变换。** 在已有 compact 表示上补足算子与整数误差/低位增长验证。规划跨多个因子矩阵的连续 tuple 批次，不能给单层变换重复记省层收益。
5. **P01/P05 满槽 LCR+AKS 与 P02 OverModRaise 独立候选。** 分别建立状态/模数条件后才接入。保留不支持的组合及具体原因；不提供“同时全开即通过”的虚构选项。若要将 LCR 与 P03 SubSum 组合，必须首先给出新的重排和范围论证。

这一路线中的第二步属于**桥接自举**，不是原论文直接给出的 MLWR 原生自举证明。当前 MLWR phase 为 `c0−Σcj sj`，OpenFHE 为 `c0+c1 s`；正负号必须在评估键嵌入中处理。可选择让桥接键加密 `−sj`，回程加密 RLWE 秘密 s，但需要独立验证实际密钥切换公式与噪声。双向评估键会形成密钥依赖，现有四篇不构成其完整安全论证。

同 N 桥接不会消除自举的高模数预算。如果把外层 N=8192 接到内层 N=65536，这已是额外的环切换/环扩展设计，必须单独标识两个 N；不能用它宣称“全流程 N=8192”。四份原件没有给出可直接移植的这个 MLWR 环切换证明。

## 6. 参数扩展应怎么呈现

参数应明确区分应用和自举，建议在现有 l/k/N/depth/scale/first/P/gadget 参数之外报告：

|类别|参数|至少需要的约束或输出|
|---|---|---|
|应用|`total_depth`, `refresh_interval`, `max_bootstraps`, `target_precision_bits`, `input_bound`|真实完整电路的误差，不只刷新前后差值|
|表示与后端|`bootstrap_backend`, `transform_method`, `slot_layout`, `slots`|原生参考、桥接、自定义 sparse 路径必须不同标签；输出实际分支|
|自举预算|`cts_budget`, `stc_budget`, `levels_after_bootstrap`, `bootstrap_scale_bits`, `bootstrap_first_mod_bits`|按实际素数链、隐藏预留/归一化层计算；返回可继续计算层数|
|密钥|`bootstrap_secret_distribution`, `ephemeral_hamming_weight`, `num_large_digits`, `bridge_gadget_bits`|所用分布/实际重量、所有键的模数与大小|
|线性变换|`cts_baby_step`, `stc_baby_step`, `precompute`, `thread_count`|合法因子、预处理时间、冷/热运行区别|
|非线性|`evalmod_K`, `evalmod_degree`, `double_angle_steps`, `range_failure_target`|K与布局/密钥模型匹配，系数及深度同步；估计失败概率与实测误差分开|
|候选专用|`lcr_aks`, `overraise_bits`, `downscale_bits`, `tuple_divisor_bits`|只有存在已验证实现的选项才可启用；其他显式拒绝并给原因|

先用预算预筛全组合，然后对可行点执行正确性/计时。有限资源下可以把 N=8192 的所有候选拒绝证据完整保存，而对较大 N 做筛选矩阵；必须列出“生成、拒绝、执行、成功、失败”各数量，不能把未执行点当作失败或通过。建议参数网格包含 N=8192/16384/32768/65536、有效槽16/64/256、目标精度15/20/25位、预算{1,1}/{2,2}/{3,3}、每轮可用层2/4/6等，按用户要求优先验证20位与N8192；这只是候选设计，不是已测矩阵。

## 7. 最小可证伪测试

|检查|最低测试内容|一票否决的现象|
|---|---|---|
|真实自举边界|评估进程不加载私钥；输入耗尽若干层；刷新后实际继续乘法；至少两轮刷新|刷新调用解密/重加密，或只改层元数据|
|桥接|k=2/3，正负/复数/边界值；单向与往返分开比较；错keytag/错基底拒绝|符号、槽次序、根/scale/level不一致；回程无法继续运算|
|安全预算|统计每个公开键/密文的真实最大模数，包含Q_over、Q×P与桥接键；固定128表检查|只检查原应用Q；用NotSet或伪造秘密分布通过|
|数值精度|至少3把新密钥、随机/符号交替/接近输入边界三类消息；高精度明文预言机；20位目标=2^-20|只报告平均有效位；大量平方衰减到0导致假通过；遗漏完整电路误差|
|LCR|准确固定整数代表元，验证未取模内积/公开保守界；首层乘法、求和、切换次序全记录|对普通旋转后的随机密文直接声称保层正确|
|OverModRaise|逐步记录模数、尺度、首次切换时刻，恢复后的新增误差|首次切换超过公开预算；多项收益重复累计|
|Tuple|精确整数核验重组、RS2、遗漏LL项；负数和舍入边界；连续矩阵因子|低位公式错误；scale遗漏d；低位增长未计入|
|Sparse|完整N/2槽的重复结构、CtS辅助槽范围、StC重建；包括小/大区间与r=4边界|只看前m槽就宣称全槽范围通过；仍用不匹配的K|
|计时|setup、普通keygen、bootstrap/bridge keygen、MLWR→RLWE、ModRaise/SubSum、CtS、EvalMod、StC、RLWE→MLWR及总时间|分段重叠；用手工归一化时间替代原始墙钟时间|

最终报告需要给每项论文技术标注“实现且实测 / 实现但未通过 / 仅算子验证 / 参数规划 / 尚未实现”，同时展示原四层版本、原生参考、桥接版和论文优化版的同条件差异。这比把四个名称列入方案更能证明实际完成了哪些工作。

## 8. 证据缺口与来源锁定

本轮已补齐：固定OpenFHE1.6.1上的公开同环桥接、P03小区间重复槽CtS/StC，以及N65536的40次连续密文乘法和8次真实刷新。原生/P03、k2/3、有效槽8/64，共72次运行全部通过，另以140位独立明文链核验117,964,800个槽值；源码、原始ZIP身份和具体时间见实测报告。默认续算显式使用folded_rlwe_hybrid，不能写成原模块gadget乘法的速度。这里的通过范围不包含作者后续SSE、大区间或自定义EvalMod参数。

仍未关闭的缺口：四技术联合在本 MLWR 分布下的安全与误差证明；N8192+20位+128表下成功自举的实测；桥接评估键的安全论证；LCR与SubSum同时使用的新重排；OverModRaise内核与原件公式疑点的作者勘误确认。LCR/AKS和OverModRaise并未接入，不能把研究路线表中的候选写成实现完成。这些缺口不应被论文已有大N结果替代。

原件 SHA-256：

- P01 `496b77c65bb80be24a7110db2db66ec54a00292115ff63b4dac39194682f066b`
- P02 `780a54b1d4158a02518ea606f7a783382c45bc63b59241c6a31fdaca267fb5a6`
- P03 用户原件 `d65b666dd5de9f09cefc8030e1f3ae3d732db005da26e9886a3c9824977bbb51`
- P05 `e09f50156cd36c59133829abf9dcb6fe759949d6dc7c15b82b3651e8599bd6da`
- P03 后续修订 `6bdf190cdd0fd2708bb0f8820faeb0e12b0be84836d1420c4f9ee8c4eda84bc4`

本文最初形成时只有文献核查，没有运行新密码实验；本节随后依据独立完成的实现与实验更新。原件和此前已发送的交付包保持不变，新结果作为本轮独立交付保存。
