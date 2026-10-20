# Current checkpoint — 2026-10-20

User goal: smaller parameters, more consecutive ciphertext multiplication, and
less complete-circuit time, using compatible ideas from four specified papers.
Branch: codex/bootstrap-four-papers. Implementation baseline: c6f7721.

Computational source frozen since abae7bd, source identity SHA256:
3cb4add7c72fcdc57c6fae227214ea74a507b6c7bea96e6e27d14a4699f03724.
1121536 fixes a C++17 test lifetime bug; ac25f4f fixes argparse prefix forwarding.
These do not change the computational source identity. Linux regression
39362418100 passes12 tests. Independent Standards/Spec findings were fixed and
rechecked; see docs/bootstrap-review.md for the exact scope.

Completed compact evidence:
- Full60 run39361886895:32 pass,28 security rejections,0 numerical failures.
  N4096 bothk:1 layer; N8192 bothk:1..5; N16384 bothk:1..10.
  All admitted results pass an independent140-digit plaintext oracle.
- Same-runner comparisons in completed compact jobs of39362418373:
  k2 five layers:4651.570342ms N16384 ->1848.464157ms N8192 (-60.26%).
  k3 five layers:8041.230312ms N16384 ->2833.337227ms N8192 (-64.76%).
  Same-N8192 four-layer changes:k2 -11.88%,k3 -18.09%.
  Same20-bit absolute-error target; actual old/new errors both retained.
  Different CPU acrossk; ratios only within each matched runner.
- Mac corroboration:7 original configurations pass; old k3/N16384/five-layer
  15-sample timing hit900s. A separate3-key/3-family,3-sample/1-warmup batch passes,
  including140-digit verification. Original failure and rejected2-sample CLI
  request preserved. Mac timings are not primary controlled speed evidence.
- Offline delivery source built from all867 bundled dependency files on Mac,
  with no dependency fetch; all12 regression tests pass. Logs, library and source
  hashes retained in the delivery evidence.

Bootstrap qualification:
- N65536 same-ring MLWR/RLWE public bridge, true EvalBootstrap, explicitly named
  folded_rlwe_hybrid continuation backend. Native and P03 small repeated-slot
  transforms; total public budget1677 <=1747 at128-classic uniform ternary.
-12-layer local diagnostics pass3 real refreshes; allN/2 output slots checked.
-39362418373 bootstrap is invalid due old --k prefix parsing; do not admit it.
- Corrected monolithic40-layer39363025867 was stopped for resource scheduling:
 18 sequential cases could exceed90min.27 completed40-layer/8-refresh cases pass
 independently; partial artifacts preserved, not a complete qualification.
- Formal replacement39367123814, commit6582e9d, currently running12 shards:
 k2/3 x slots8/64 x trial1/2/3. Each same-runner pair has native3 families then
 P033 families, one fresh key per process. Total72 cases, unchanged mathematics,
 inputs and precision. Per-case900s, per-job120min. No result admitted early.
- merge_bootstrap_shards.py is frozen at the run's checker hash; requires all12
 shards, exactk/slots,40 multiplications,8 refreshes,50*N/2 checked slots, source/
 binary/dependency identities. Speed uses median of3 within-runner ratios.
 New merge/scheduling tools are not covered by the earlier independent review.

Limits: N8192 five-layer compact is not N8192 bootstrapping. P01/P05 are versions
of the same LCR/AKS work. No LCR, AKS, OverModRaise, SSE, ring switching or full
MLWR security proof is claimed.64-point bootstrap budget screen is only a budget
screen (12 allowed), not executed correctness evidence.

Delivery is INCOMPLETE until the72-case batch is collected and admitted. Code,
parameter guide, original papers, failed diagnostics, source snapshots and bundled
upstream sources are prepared. HTML/PDF final tables require final measured data;
PDF visual QA and complete ZIP manifests must precede delivery. Draft PR1 exists:
https://github.com/leemaple/mlwralg/pull/1.
