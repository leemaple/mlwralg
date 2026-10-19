# MLWR 参数修改手册

2026 年 10 月 19 日 · 适用于支持运行时配置的新版本

## 1. 最常用的修改方法

现在可以自己修改 l、k、N。l 和 k 相互独立，不要求相等；默认仍是 l=k=2。N 表示环维度，不是槽数。首次更新到本版本后需要编译一次，之后改配置文件即可，无需反复改源码或重新编译。

**要改的文件：configs/default.conf。** 建议复制为 configs/my.conf，用记事本、VS Code 或其他纯文本编辑器修改；保存为 UTF-8。不要用 Word 直接编辑配置文件。

```sh
cp configs/default.conf configs/my.conf
```

例如只想把 l 改成 3、k 保持 2、N 明确指定为 32768，并使用 16 个槽，把对应行改成：

```ini
l = 3
k = 2
N = 32768
slots = 16
```

其余参数保留默认。也可直接使用仓库里的 configs/l3-k2-n32768.conf。该示例为了快速检查，使用 3 次正式采样、1 次预热；论文计时应恢复 15 次采样、2 次预热或更高。

在项目根目录执行下面三步。第一步只生成参数，不生成密钥，不代表正确性已经通过。

```sh
./build/mlwr_experiment --config configs/my.conf --print-parameters
python3 scripts/run_experiment.py build/evidence/my-run build/mlwr_experiment --config configs/my.conf
python3 scripts/verify_experiment.py build/evidence/my-run/experiment.json
```

命令优先级为：内置默认值 < 配置文件 < 命令行选项。例如在运行命令后追加 --l 1 --k 3，会临时覆盖文件中的 l、k，不会修改文件。选项写在 --config 前后都一样。重复键、未知键、漏填值和错误数字会报错。

没有命令行环境时，可按第 4 节直接在 GitHub 网页填配置、运行 Linux 实验，再下载结果。

<!-- page -->
## 2. 算法结构和 OpenFHE 参数

下表的范围是本实现接受的配置范围，不代表所有组合都通过数值验收。参数之间仍须满足模数、尺度、槽数和 OpenFHE 参数表的约束。

| 配置键 | 默认值 | 范围与含义 |
|---|---|---|
| l | 2 | 1..8；公钥行数、加密随机向量长度。可与 k 不同。 |
| k | 2 | 1..8；秘密向量长度。普通密文有 k+1 个分量，重线性化有 k² 行。 |
| N | 0 | 0 自动选择；或 1024..131072 内的 2 的幂。默认配置实际生成 32768。 |
| depth | 3 | 1..6；申请的乘法深度，影响主模数链长度。 |
| slots | 8 | 1..65536 内的 2 的幂，且不超过实际 N/2；表示一个向量的复数槽数。 |
| scale_bits | 50 | 41..59；缩放素数的目标位数，影响每次重缩放的除数和精度。 |
| first_mod_bits | 60 | 整数，scale_bits < first_mod_bits ≤ 60；主链首素数位数。 |
| security_bits | 128 | 128、192、256；选择 OpenFHE 的 classic RLWE 参数表。 |

**N 的改法。** N=0 让 OpenFHE 按深度、模数位数和安全级别自动选择。手动 N 太小，即使是 2 的幂也会被拒绝，并提示所需维度。改大深度或安全级别后，先保留 N=0 查看实际结果，再决定是否固定它。程序不会自动关闭安全表检查。

**l、k 的影响。** 公钥含 l×(k+1) 个环元素；重线性化密钥含 k²×(k+1) 个环元素。因此增大 k 往往显著增加内存和计算量，不能简单认为 k 从 2 到 4 只慢一倍。1..8 是当前工程限额，不是安全范围结论。

**depth 的含义。** 它控制模数链，实验报告仍计时一次两密文乘法。把 depth=6 不会自动把实验电路改成连续六次乘法，也不能证明任意六层电路都满足目标误差。默认历史回归另有三层连续平方检查。

security_bits 只是共有 OpenFHE 参数的选择标签。改变 l、k 或把该值设为 256，都不能代替本修订 MLWR 构造的安全性证明。

<!-- page -->
## 3. 尺度、精度、消息和解密噪声

| 配置键 | 默认值 | 范围与含义 |
|---|---|---|
| initial_scale_bits | 0 | 0 使用 OpenFHE 初始尺度；或 40..100，显式令初始 Δ=2 的该次方。 |
| precision_bits | 20 | 1..50；验收门槛为最大复数绝对误差 ≤ 2 的负该次方。 |
| message_bound | 2 | 有限数，0 < 值 ≤ 1024；公开的输入幅度上限，允许小数。 |
| smudge_bound | 0 | 0..1073741824；解密时每系数添加 [-B,B] 内的独立均匀整数噪声。0 不加。 |
| rotation_steps | 1 | -65536..65536；正数向左旋转，负数向右旋转，0 不移位。 |

**三个不同的量。** scale_bits 控制缩放素数的位数；initial_scale_bits 控制最初编码尺度；precision_bits 是结果必须达到的误差门槛。提高验收门槛不会自动增加实际精度。默认初始尺度约为 2 的 69.585 次方，首次准备重缩放后约为 2 的 50 次方，因此 initial_scale_bits=50 不是“保持默认精度”的写法。

建议先保持 initial_scale_bits=0。确需独立改变 Δ 时，可从 70 做对照，并查看每条结果的 scale、log2_scale 和 inverse_scale。手动尺度必须在每个阶段满足模数预算；输入值合法也可能因重缩放后尺度不足而停止。程序始终拒绝低于 2 的 40 次方的实际尺度。

**幅度如何生效。** 演示和实验把原有测试向量乘以 message_bound/2，再以该值作为公开幅度声明。随机消息也随之缩放。值越大，乘法后的幅度预算越大；1024 是输入上限，不承诺该值能在所有模数配置下完成乘法。论文比较时应固定输入幅度。

**噪声如何生效。** smudge_bound 作用于实际 Decrypt，包括解密计时；底层相位误差界仍检查加噪前的算法相位。非零噪声可能让精度验收失败。这个选项用于研究原文 flooding 步骤，当前未给出满足特定安全声明的噪声参数证明。

报告同时保留实际误差、有效位数、1/Δ 和是否满足 1/Δ。降低 precision_bits 只会放宽验收，不能写成算法精度得到改善。

<!-- page -->
## 4. 实验重复次数、随机消息与网页运行

| 配置键 | 默认值 | 范围与含义 |
|---|---|---|
| key_trials | 3 | 1..100；正确性检查使用的独立新密钥组数，每组测试实数、复数、随机消息三对输入。 |
| message_seed | 20261013 | 0..4294967295；仅控制公开随机测试消息，不控制秘密或加密随机量。 |
| samples | 15 | 3..1000；每项操作的正式计时次数。 |
| warmups | 2 | 1..100；每项操作计时前的预热次数。 |

以上 17 项都可写入同一份配置文件。命令行形式为键名前加 --，下划线改连字符；例如 precision_bits 对应 --precision-bits，N 对应 --n。配置文件 # 后面的内容是注释，不支持表达式：写 N=32768，不写 N=2^15。

**通过 GitHub 运行。** 打开 https://github.com/leemaple/mlwralg/actions，选择“MLWR and OpenFHE correctness”，点击“Run workflow”，选择 main，在 parameters 输入框粘贴 key=value 设置，用英文分号分隔；也兼容换行。空白会运行默认检查；填写内容会在默认检查完成后追加自定义实验。点击运行后，查看 Test and record parameters、Run user parameters 的日志。

示例网页配置（未写的项使用默认值）：

```text
l=3;k=2;N=32768;slots=16;samples=3;warmups=1;key_trials=1
```

完成后下载 correctness-evidence-linux。自定义结果位于 experiment-custom；默认实验和自动配置回归位于其他目录。key_trials=1、samples=3 是快速检查设置；正式实验请恢复或增加重复次数。

如果没有 Run workflow 按钮，需要使用有该仓库运行权限的账号。Windows 可采用网页方式或 WSL2 的 Linux 构建流程；本次没有验证原生 Windows 编译器。macOS 与 Linux 的命令一致。

<!-- page -->
## 5. 怎么看结果、报错和复现

| 输出文件 | 直接能看到什么 |
|---|---|
| parameters.csv | 每项请求值与实际采用值，适合用 Excel 打开。 |
| resolved.conf | 可复用配置；N=0 已替换为本次实际环维度。 |
| experiment.json | 完整参数、四类模数、实际尺度、逐槽数据、测量样本与源代码指纹。 |
| correctness.csv / slots.csv | 汇总误差、有效位数、严格 1/Δ 比较及逐槽期望值/解密值。 |
| timings.csv / timing-samples.csv | 14 项操作的统计量与每次原始毫秒数。 |
| experiment.log / failure.json | 失败阶段与运行日志；失败时不会产出新的成功结果。 |

程序先通过正确性检查，再计时。计时单位是处理一个 slots 长度向量的一次调用，不能把不同槽数或机器上的数值直接当作同条件加速比。旋转计时名称在新版 JSON 中为 rotate，具体步数写在 protocol.rotation_steps。

**复现一次运行：** 把已有目录中的 resolved.conf 复制到 configs/replay.conf，再指定一个新的输出目录。配置相同不代表密文、随机密钥或耗时逐字相同；密码随机量仍重新采样。不要把新结果写进此前的证据目录，运行脚本会清除该输出目录的旧结果。

常见报错及处理：

- “does not comply with HE standards”：N 太小。改为 N=0，或按提示增大；不要降低安全检查来掩盖问题。
- “slots must not exceed N/2” 或 “power-of-two slots”：修正槽数；例如 N=32768 时最多 16384 槽。
- “Scale or public message bound exceeds modulus budget”：尺度、消息幅度或剩余模数不匹配。先恢复 initial_scale_bits=0、message_bound=2，再逐项调整。
- “configured precision target”：实测误差没达到门槛。检查尺度、噪声、幅度和电路，不能把失败写成通过。
- “Unknown parameter” / “Duplicate”：检查键名与重复行。参数大小写按示例填写，尤其是小写 l（字母 ell），不是数字 1。

正确性回归入口为 ctest --test-dir build --output-on-failure。原四组测试保留，另有可变参数运算测试与配置入口测试；默认 OpenFHE 数值参数仍与原固定参数文件逐项一致。已覆盖不相等的 l、k，N=16384/32768/65536，1/4/8/16 槽，以及错误向量维度拒绝。未穷举所有合法组合，每次自定义实验仍须重新验收。

<!-- page -->
## 6. 源码入口与固定项

| 要检查或修改的内容 | 文件 / 入口 |
|---|---|
| 自己改运行参数 | configs/default.conf；无需改 C++。 |
| 默认值、参数键和范围 | include/mlwr/options.hpp；src/options.cpp。 |
| OpenFHE 参数生成和 N 检查 | src/profile.cpp / OpenFheProfile。 |
| 可变维度的密钥与运算 | include/mlwr/scheme.hpp；src/scheme.cpp。 |
| 实际测试输入、正确性和计时 | apps/mlwr_experiment.cpp / Correctness、Benchmark。 |
| 参数快照、CSV 和机器信息 | scripts/run_experiment.py。 |
| 从原始数据重算误差与统计量 | scripts/verify_experiment.py。 |
| 新增回归 | tests/parameter_checks.cpp；tests/test_parameters.py。 |

直接调用 C++ 库的例子：

```cpp
auto profile = mlwr::OpenFheProfile(
    3, 16, 32768, 50, 60, 128);
// 顺序：depth, slots, N, scale_bits, first_mod_bits, security_bits
mlwr::ResearchScheme scheme(profile, 3, 2);  // 顺序：l, k
auto keys = scheme.KeyGen();
auto plaintext = scheme.Encode(values, 0, 2.0);  // 自动初始尺度
// 高级调用：Encode(values, level, public_bound, explicit_scale)
```

**以下不作为自由开关。** OpenFHE 固定为 1.6.1，64 位整数、MATHBACKEND=4；使用 COMPLEX、UNIFORM_TERNARY、FLEXIBLEAUTOEXT 和单 digit 的 HYBRID 辅助基。改变这些会涉及实现与误差界，不是填写一个参数即可保证正确。

主模数 P、辅助模数 Q 的素数和单位根由 OpenFHE 生成；公钥模数 T、源模数 W 自动构造，满足 T>P、W>max(T,PQ)。精确素数、log2 模数都可以查看，但不提供任意替换素数的配置入口。新增独立链的额外 30 位塔仍固定。

没有单独的明文模数 t。本修订实现直接使用浮点编码尺度；每次重缩放实际除掉末尾模数塔。Rescale 的 dropped_towers 属于 C++ 调用参数，实验固定一次丢一塔；任意多丢可能立即破坏尺度预算。

改参数后应创建新的 ResearchScheme 并重新生成公钥、秘密、重线性化密钥和旋转密钥。不要混用不同上下文、参数或轮次的密钥和密文；程序会检查身份、尺寸、层级、尺度和模数基。

编译资源参数另有 MLWR_BUILD_JOBS（默认 4）和 MLWR_DEPENDENCY_DIR（依赖目录）。它们影响构建，不属于算法参数。首次构建方法见 README；新版本无自举，安全性仍未证明，参数化不会改变这一实现边界。
