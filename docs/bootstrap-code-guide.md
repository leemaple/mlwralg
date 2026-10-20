# 这次具体做了什么，代码怎么看

比较起点是已交付的 `c6f7721`。本轮计算实现冻结在 `abae7bd`；`1121536` 修复测试对象生命周期，`ac25f4f` 修复批量自举脚本的参数透传。三者的计算源身份一致，后续交付文档有独立提交。先看结果总览，再用下表定位，无需从头读全部源码。

|改动|代码入口|直接能检查到的事实|
|---|---|---|
|同样k减少重线性化工作|`src/compact.cpp`：`RelinGen`、`RawRelin`|先合并非对角线 aᵢⱼ+aⱼᵢ，再做平衡分解；k=2为4→3个秘密乘积，k=3为9→6个|
|把N8192的模数预算利用得更充分|`src/profile.cpp`：`CompactProfile`、`PackedLargerBasis`|允许27.83等素数对数目标；输出实际素数和根；独立公钥T按整数目标装入较少塔，仍检查T及QP|
|真正的公开桥接自举|`include/mlwr/bootstrap.hpp`、`src/bootstrap.cpp`|`KeyGen`离线生成公开换钥；`Fold`用−s₀统一相位；`Refresh`调用真正EvalBootstrap；`Import`返回合法模块行|
|消除重复槽外噪声并能继续计算|`BootstrapBridge::ProjectRepeated`|实际旋转求和，再实际乘整数A及丢一个素数重缩放；没有仅改层号或scale来伪装正确|
|快速续算后端|`BootstrapBridge::HybridMultiply`|加密因子精确投影到同层，保留实际尺度；原生张量积→重线性化→重缩放，返回模块行。明确标为折叠RLWE/HYBRID|
|原模块大模数参考路径|`src/gadget.cpp`、`src/scheme.cpp`|公共平衡分解切换；可保留module乘法用于对照，生成密钥时间单独报告|
|论文P03的稀疏CtS/StC|`patches/openfhe-p03-small.inc`|重复槽的小区间掩码、旋转归并、StC重建；保留OpenFHE原生EvalMod、均匀三元分布和安全检查|
|只补丁指定依赖版本|`scripts/patch_openfhe_sparse.py`、`build_openfhe_p03.sh`|固定源文件SHA，精确锚点替换；原依赖不改；单独安装与manifest，编译时核对补丁和库哈希|

## 正确性证据在哪里

- `tests/compact_checks.cpp`：不等复数输入乘法、对称交叉项、密钥行数、完整代数恒等式、T独立性及根。
- `tests/standard_gadget_checks.cpp`：k=3、小P的模块乘法、换钥、旋转、错误元数据拒绝。
- `tests/bootstrap_checks.cpp`：k=3公开折叠/导入，完整槽位解码；错误k、重排/空/错误目标评估键、上下文、层、基底和尺度拒绝。
- `tests/test_sparse_transform_oracle.py`：纯数学全辅助槽变换及被StC使用的系数；不把它当作已完成加密自举。
- `apps/mlwr_bootstrap.cpp`：客户端生成测试密文，在评估调用外解密检查每一步；记录每个全槽输出和阶段耗时。
- `scripts/verify_bootstrap.py`：独立140位十进制明文乘法，不调用C++参考值或OpenFHE；核对完整槽位、真实层恢复、安全表、误差、总时间。
- `scripts/run_bootstrap.py`：三把新密钥×三类消息，禁止把单刷新探针记成资格化；保存失败和哈希。

`Refresh`、`HybridMultiply`、`ProjectRepeated`的接口没有私钥参数，也不调用解密/重加密。`apps/`里的解密只用于实验验收。评估键仍带来额外安全假设，128参数表不是这套桥接的完整安全证明。

## 时间怎么核对

compact 的 `multiply_tensor`、`multiply_relinearize`、`multiply_rescale`来自同一次乘法，`multiply_total`是合计；`depth_square_circuit`是完整连续平方。不要把三个独立最佳样本相加。

bootstrap 每条记录的 `ms`是该完整评估操作；`phases_ms`进一步拆解折叠、内核、归一化、归并、导入，以及乘法三阶段。原生内核stderr中的 CtS/EvalMod/StC 是内核内部子阶段，**不能再加到已包含它们的总时间里**。setup与各类keygen另列；端到端部署一次性成本应另行加上这些项目和输入加密。

## 四篇论文的使用边界

P03小区间已形成可运行自举路径；P02的高低位表示与现有compact有联系，但本轮没有宣称完成OverModRaise内核。P01/P05的LCR/AKS尚未接入，原因是当前稀疏旋转后的状态不满足直接保层前提。完整文献定位、版本差异、原件哈希在 `docs/bootstrap-paper-research.md`。

因此，实际收益必须从“小参数五层”“对称/紧凑公钥的时间变化”“原生与P03的同条件自举时间”三类数据分别读出，不把论文里的倍数当作本实现的测量值。
