# 小参数乘法与自举：参数修改手册

本轮目标是在相同精度验收门槛下做更多连续密文乘法、减少完整电路耗时。请先选择下面两条用途，再改对应文件。参数通过配置文件或命令行传入，修改后不用重新编译；更换源码或 OpenFHE 补丁时才需要编译。

## 1. 我应该用哪份配置

|用途|配置文件|实现与验收口径|
|---|---|---|
|使用较小 N，运行本轮已测的 5 层电路|`configs/compact/n8192-depth5.conf`|MLWR 高低位密文，N=8192，l=2，k=2；k=3 可覆盖。连续平方逐层对照明文，最大复误差 ≤2⁻²⁰|
|计算更深电路，需要真正刷新密文|`configs/bootstrap/native-n65536.conf`|同环 MLWR→RLWE 公开桥接，OpenFHE 原生自举，刷新后用显式标记的 HYBRID 后端乘法|
|测试四份论文中稀疏变换的实际收益|`configs/bootstrap/p03-n65536.conf`|同一桥接，CtS/StC 改为 P03 小区间重复槽算法；需单独补丁构建|

N=8192 五层配置不是自举配置。N=65536 自举不能被写成“8192 自举”。所有数值通过状态及速度以交付包的结果总览和原始数据为准；配置存在不代表每个改值都能通过。

## 2. 最短操作步骤

所有命令在仓库根目录运行。不能在本机方便运行时，可直接使用 GitHub Actions，见第 6 节。

```sh
# 普通版构建一次
bash scripts/build_openfhe.sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DOpenFHE_DIR="$PWD/.deps/openfhe-install/lib/OpenFHE"
cmake --build build --parallel 4

# 复制配置，改 l/k/N/深度等；命令行覆盖文件中的同名值
cp configs/compact/n8192-depth5.conf configs/my-depth5.conf
./build/mlwr_experiment --config configs/my-depth5.conf --k 3 --print-parameters
python3 scripts/run_experiment.py build/evidence/my-depth5 build/mlwr_experiment \
  --config configs/my-depth5.conf --k 3
python3 scripts/verify_experiment.py build/evidence/my-depth5/experiment.json
```

先看 `--print-parameters` 是否成功，再运行实验。每次使用新的输出目录，保留失败记录；不要用换随机密钥重跑并覆盖的方法挑选“通过”。正式批次至少三把新密钥、每把三类消息。

## 3. 小参数模式可以改什么

|文件中的名字|建议起点／取值|影响与注意事项|
|---|---|---|
|`l`, `k`|2、2；分别支持1..8|独立的模块维度。k 增大通常增加密钥、计算量及噪声；不是普通性能旋钮|
|`N`|8192；2 的幂|环维度，影响时间、内存和可承受模数。compact 必须显式给定，不能用0自动增大|
|`depth`|5；1..10|实际执行该层数的连续平方；增大后必须重新通过完整公开模数和正确性检查|
|`slots`|8；2 的幂且≤N/2|有效消息槽数；增大后须重新测误差和时间|
|`scale_bits` / `scale_log2`|27 / 27.83|后者是重缩放素数的对数目标，前者必须等于其向下取整。0表示使用原来的整数位数生成方式；实际素数另行输出|
|`first_mod_bits`|46|链尾保留的首模数位数。过小会导致末层幅度预算不足，过大占用安全预算|
|`divisor_bits`|16；16..40|高低位分解除数的位数；会同时影响精度、模数预算及尺度|
|`public_extra_bits`|17；16..40|辅助 P 以及独立公钥 T 的目标余量；降低不一定仍能满足正确性|
|`gadget_bits`|20；4..30|重线性化分解位数；位数小→更多数字和密钥行，通常噪声更小、计算更多|
|`rotation_gadget_bits`|14；4..30|旋转独立设置，需验证末层旋转精度|
|`symmetric_relinearization`|1|将 k² 个秘密乘积合并为 k(k+1)/2 个，再分解和换钥；0保留原路径|
|`packed_public_key`|1|按实际目标把独立公钥 T 装入较少的 NTT 素数，避免逐塔配对的额外膨胀；仍检查完整 T 和 QP|
|`precision_bits`|20|验收阈值为2⁻precision_bits。另行报告实际误差、有效位数及严格1/Δ比较；不能把降低精度写成同精度优化|
|`security_bits`|128；128/192/256|OpenFHE classic RLWE 参数表档位；不等于已证明修订 MLWR 的安全性|
|`message_bound`|2|公开输入幅度上限；不能按实际秘密明文临时放松预算|
|`samples`, `warmups`, `key_trials`|15、2、3用于正式对照|计时次数、预热次数、新密钥次数。正确性失败不计时|
|其他已有参数|`message_seed`, `rotation_steps`, `smudge_bound`, `initial_scale_bits`|具体含义见原 `docs/parameter-guide.md`；已有接口保留|

128 档均匀三元表的公开模数上限：N4096=109位、N8192=218位、N16384=438位、N32768=881位、N65536=1747位。检查的是实际整数模数；自举另包含 native QP、module QP、公钥 T。不能只把配置中的位数相加就认定通过。

## 4. 自举模式可以改什么

```sh
# 构建独立补丁依赖；原 openfhe-src 不被修改
bash scripts/build_openfhe_p03.sh
cmake -S . -B build-p03 -G Ninja -DCMAKE_BUILD_TYPE=Release -DMLWR_P03_PATCH=ON \
  -DOpenFHE_DIR="$(cat .deps/p03-openfhe-dir.txt)"
cmake --build build-p03 --parallel 4

# 原生与 P03 使用同一二进制，只切换变换
./build-p03/mlwr_bootstrap --config configs/bootstrap/p03-n65536.conf --print-parameters
python3 scripts/run_bootstrap.py build/evidence/my-bootstrap build-p03/mlwr_bootstrap \
  --config configs/bootstrap/p03-n65536.conf --key-trials 3 --timeout 900 \
  --experiment-class qualification --circuit-depth 40
```

|参数|预置值|含义|
|---|---|---|
|`N`, `l`, `k`, `slots`|65536、2、2、8或64|自举与外层密文使用同一 N；没有环切换。有效槽在完整 N/2 槽中重复|
|`security_bits`|128；128/192/256|完整公开模数按所选档重新检查；本轮正式对照固定128|
|`precision_bits`|20；8..40|最大复数绝对误差目标2⁻precision_bits；不能以放松门槛当作同精度改进|
|`scale_bits`, `first_mod_bits`|55、56|前者41..59，后者必须更大且≤60；自举的精度与首模数。不能直接照搬小参数模式的27.83|
|`usable_levels`|8；1..20|加在内核自举预算之上的层数，**不是保证每轮可用8次乘法**。两轮校正、归并规范化会消耗层数；程序输出真实层号|
|`cts_levels`, `stc_levels`|1、1|原生支持1..4；P03小区间当前只支持1/1|
|`large_digits`|5；1..8|HYBRID 分组数；某些组数不能分配当前塔数，会明确拒绝|
|`module_gadget_bits`|30；4..30|模块参考引擎的平衡分解位数。0启用原来的大 P 方式，通常更大更慢|
|`iterations`, `correction_precision`|2、12|实际两轮自举误差校正；第二项须在1..30。单轮的失败诊断保留，不当成通过|
|`paper_sparse`|0原生／1论文变换|P03只实现8×slots²≤N的小区间。未实现的大区间明确拒绝|
|`project_repeated`|1|公开求和归并重复槽，然后真实整数乘法与一次重缩放来统一尺度；消耗层数和时间均计入|
|`flexible_scaling`|1|归并续算要求 FLEXIBLEAUTO。关闭只用于特定诊断，不是推荐路线|
|`hybrid_multiply`|1|刷新后的显式折叠 RLWE/HYBRID 密文乘法。0使用原模块 gadget 乘法；其大模数重线性化密钥生成可能很慢|
|`circuit_depth`|20；1..100|完整的连续密文乘法次数，与输入耗尽后发生的实际刷新次数分别输出|
|`family`|0、1、2|符号交替实数、非对称复数、正弦余弦消息；批量脚本自动覆盖三类|
|`correction_factor`|0自动；0..20|OpenFHE内部修正参数；除非有可验证的实验依据，保持自动|
|`refresh_probe`|0|1仅检查一次刷新、无续算。正式资格化禁止使用此开关|

本自举电路是 `m₀ × μ × … × μ`，每次 μ 都以密文参与，`|μ|=0.985`，40次后幅度仍约为初始值的0.546倍。它与 compact 的连续平方电路不同，两者耗时不能直接相除冒充加速比。

自举的接口范围为N=4096..131072的2次幂，l/k分别1..8，slots是≤N/2的2次幂；通过数值范围检查仍需通过安全预算和真实计算。配置文件写 `N`、`scale_bits`，命令行对应 `--n`、`--scale-bits`。重复键、未知参数和非法数值会被拒绝，命令行同名参数可覆盖配置文件。

批量脚本另有三个参数，只写在 `run_bootstrap.py` 命令行，不放进自举配置文件：`--key-trials` 为每个消息族的新密钥次数（1..10，正式单批至少3）；`--timeout` 为每个C++进程的秒数（40层使用900）；`--experiment-class` 为diagnostic或qualification。独立明文复算时间不计入这个C++进程上限。分片模式每片设1次和diagnostic，全部三片核验后才合成资格化结果。

## 5. 结果看哪里，怎样判断改得对

compact：`experiment.json` 包含实际素数／单位根、参数、逐槽误差、每层误差和计时；`depth-correctness.csv` 看完整深度；`timing-samples.csv` 保留原始样本。

bootstrap：`summary.csv` 先看每把新密钥/消息类的状态；各目录 `output.json` 包含完整 N/2 槽、真实层号、乘法与刷新时间；`oracle.json` 是独立140位十进制明文复算；`stderr.log` 有 CtS、EvalMod、StC 原始计时。`evaluator_total_ms` 包含因子折叠、所有乘法与刷新、归并和导入，客户端解密验收另计。密钥生成及 setup 单独列出，不能隐藏在总时间之外而不说明计时边界。

底层 `output.json` 保守地保留 `experiment_class=diagnostic` 标签；只有外层 `run_bootstrap.py` 完成新密钥数量、续算范围、层恢复、哈希与独立误差核验之后，批次 `summary.json` 才会写出 `experiment_class=qualification`。应看批次标签和逐次状态，不要手动改写底层记录。

长电路使用分片时，每片仍标为 diagnostic，只含每类消息一把新密钥。`merge_bootstrap_shards.py` 要求全部12片、72次逐槽核验及源身份一致后，才写出完整批次 qualification；保留原始文件字节，并在外层索引中说明分片编号。单片或缺失数据不能直接作为完整资格化。

“参数被安全表拒绝”“精度不通过”“运行失败”“独立复算失败”含义不同。前三者都不能记为成功，也不能把缺失耗时写成0。1/Δ 的严格门槛通常比20位目标更严格，必须保留其独立结果。

这里的误差位数定义为 `-log2(最大复数绝对误差)`，不是相对误差有效数字，也不是 double 的52/53位尾数长度。报告比较的是相同的20位绝对误差**目标**；旧配置的实测误差可能更小，前后实际误差都保留，不能把这点写成实际精度完全不变。

## 6. 不在本机运行：GitHub入口

在 [项目 Actions](https://github.com/leemaple/mlwralg/actions) 选择分支 `codex/bootstrap-four-papers`：

1. **MLWR and OpenFHE correctness**：编译和回归检查。
2. **Optimized compact full 60 combinations**：固定 l=2、k=2/3、N4096/8192/16384、深度1..10；新版本全部组合，拒绝项也留档。
3. **Bootstrap and compact matched qualification**：同一 runner 的原生/P03 对照，以及原四层/优化四层、原N16384五层/新N8192五层对照。`suite` 可选 all/bootstrap/compact；`circuit_depth` 可选40/20/60/80，默认40。这些是待测深度选项，不能仅凭下拉框存在就宣称已通过。
4. **Sharded matched 40-layer bootstrap qualification**：本轮40次乘法正式批次入口。k=2/3、slots=8/64、trial=1/2/3，共12片；每片在同一runner和二进制上先原生后P03，各跑3个消息族，每次生成新密钥。每种参数/变换合计9次。

原单任务安排每个runner顺序运行18次，在90分钟预算内可能截断，现分为每片6次、每次900秒、每片120分钟预算。算法、消息族、精度门槛及总样本数不因此改变。时间比值先在每片同机计算，再汇总3个比值；不同CPU不能直接用合并绝对时间相除。

```sh
# RUN_ID 替换为刚完成的分片工作流编号；输出目录须未被其他批次使用
gh run download RUN_ID --dir build/shard-artifacts
python3 scripts/merge_bootstrap_shards.py build/merged-bootstrap \
  build/shard-artifacts/bootstrap-shard-*
```

合并脚本须使用运行批次的同一提交，检查脚本本身的哈希也参与验收。先看 `qualification-admission.json` 的72次状态，再看每组 `matched-comparison.json` 中各runner的CPU、原生/P03中位时间与同机比值。各 `summary.json` 的 `runner_environments` 能定位每次运行的机器；`source_trial` 与 `source_case` 保留分片本来的编号。

本轮发布还加了一道独立核验：`scripts/audit_bootstrap_shard.py` 核对 GitHub 原始附件ZIP摘要、全部解压文件、固定源身份及运行脚本，并重新计算每份输出的140位明文链。交付中的 `evidence/independent-shard-audits` 保存逐片核验结果。日常改参后也可以直接运行 `python3 scripts/verify_bootstrap.py 某次运行/output.json` 重算全槽误差；不要仅依据缓存的 `all_passed` 字段。

配置文件的默认续算深度为20。若复现实验中的40次乘法，在 `run_bootstrap.py` 命令后加 `--circuit-depth 40`。该值超过预置24层初始模数链，依赖真实刷新；是否通过必须看本次输出。

本轮还提供64个自举参数点的**预算预筛**：N8192/16384/32768/65536、槽数8/64、usable_levels4/8、大分组3/5、原生/P03。12点通过预算，52点被配置或安全表拒绝，详见交付包 `evidence/bootstrap-budget-screen/summary.csv`。这64点没有执行加密或自举；实际续算资格化使用单独的结果表，二者不能混计。

完整交付包附带固定 OpenFHE 与 cereal 源码；已具备 C++17 编译器、CMake、Ninja、Python3 的 Linux/macOS 可在包根目录执行 `python3 build_offline.py --jobs 4`，不需要联网下载依赖。加 `--audit-only` 只校验依赖身份；加 `--native` 构建无论文补丁版本；`--build-dir /绝对路径` 可把生成文件放到包外。默认生成到包内 `.offline`。本轮已在Mac上用包内867个依赖文件完整构建并通过12项回归，日志见 `evidence/offline-build-macos`。Windows本机本轮未验证，可直接使用上述 Linux Actions 结果，不把平台未测写成已通过。

运行完成后下载页面下方 Artifacts。只看绿色运行标记不够，还要打开汇总的逐组状态；60组里存在被安全表正确拒绝的项时，工作流也可以正常完成。

## 7. 哪些“论文开关”没有提供

四份原件中 P01/P05 是同一 LCR/AKS 研究的两版。其保层条件不能直接用于含旋转换钥的重复槽 SubSum，OverModRaise 也需要重新安排首次切换及临时模数。当前没有提供虚假的 `lcr=1` 或 `overraise=1` 开关。已迁移的论文稀疏变换、已有高低位表示和本轮工程优化均能定位到代码；其余候选及不兼容原因见 `docs/bootstrap-paper-research.md`。
