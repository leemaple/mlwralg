# Current checkpoint — 2026-10-20

User goal: smaller parameters, more consecutive ciphertext multiplication, and
less complete-circuit time, using compatible ideas from four specified papers.
Branch: codex/bootstrap-four-papers. Implementation baseline: c6f7721.

Computational source frozen since abae7bd, source identity SHA256:
3cb4add7c72fcdc57c6fae227214ea74a507b6c7bea96e6e27d14a4699f03724.
1121536 fixes a C++17 test lifetime bug; ac25f4f fixes argparse prefix forwarding.
Later publishing tools and docs do not change this computational identity.

Completed compact evidence:
- Full60 run39361886895:32 pass,28 security rejections,0 numerical failures.
  N4096 bothk:1 layer; N8192 bothk:1..5; N16384 bothk:1..10.
  All32 admitted configurations pass independent140-digit plaintext recomputation.
- Same-runner compact jobs of39362418373:
  k2 five layers:4651.570342ms N16384 ->1848.464157ms N8192 (-60.26%).
  k3 five layers:8041.230312ms N16384 ->2833.337227ms N8192 (-64.76%).
  Same-N8192 four-layer changes:k2 -11.88%,k3 -18.09%.
  Same20-bit absolute-error target; actual new five-layer errors are larger.
  Full public modulus budget267 ->218 bits. Ratios only within matched runners.
- Mac corroboration:7 original configurations pass; old k3/N16384/five-layer
  15-sample timing hit900s. A separate3-key/3-family,3-sample/1-warmup batch passes,
  including140-digit verification. Original failure and rejected2-sample CLI
  request preserved. Mac timings are not primary controlled speed evidence.
- Linux standard regression39362418100 passes12 tests. The delivery source also
  builds offline on Mac from867 bundled dependency files and passes all12 tests.

Bootstrap qualification COMPLETE:
- Formal run39367123814, commit6582e9d, all12jobs success:
  k2/3 x slots8/64 x trial1/2/3. Each matched runner has native3 families thenP033
  families, one fresh key per process. All72 cases complete40 multiplications
  and8 real refreshes. Full public budget1677 <=1747,128-classic uniform ternary.
- All12original ZIPs match GitHub's SHA256. The independent external audit binds
  every file, source identity, run/verifier hash and job record, and recomputes
  all117,964,800 output slot values using Decimal140. All72 pass; maximum error
  7.938609959920634e-8, below2^-20. Keep all raw observations unchanged.
- P03 versus native complete-evaluation time, median of3 within-runner ratios:
  k2/s8 +2.531%, k3/s8 +1.101%; all3shards slower in each8-slot group.
  k2/s64 -8.198%, k3/s64 -7.433%; all3shards faster in each64-slot group.
  Preserve fixed AB ordering/different-new-key limitations; no significance claim.
- Default continuation is explicitly folded_rlwe_hybrid. N65536 same-ring bridge
  is not N8192 bootstrapping. Repeat-coded full32768slots are not32768independent
  messages. Key preparation is reported separately from evaluator totals.
- Frozen merge checker SHA is recorded in each admission. New publishing gate
  audit_bootstrap_shard.py was independently reviewed on Standards and Spec axes;
  both P2 timing/oracle identity findings fixed and rechecked. Earlier C++ P1/P2
  findings also fixed. Source review is not a security proof.

Failures and partial evidence preserved separately:
-39362418373 bootstrap invalid because old --k prefix parsing could executek2
 for a requestedk3. Its compact jobs use a different parser and remain valid.
-39363025867 monolithic batch cancelled for resource scheduling;27 complete
 40-layer/8-refresh cases and interrupted records retained, not formal72evidence.
-21early diagnostics, mathematical transform tests,64point budget-only screen
 (12allowed/52rejected), source snapshots, and Pro consultation retained.

Limits: only P03's small repeated-slot transform is ported. P01/P05 are versions
of one LCR/AKS work. No LCR, AKS, OverModRaise, SSE, ring switching or full MLWR
security proof is claimed. Smaller-N bootstrapping remains unresolved.

Delivery assembly and verification are complete. Six PDF pages were visually
reviewed; 547 local HTML links/anchors pass. All3512 manifest entries pass, and
all5 ZIPs were independently read through CRC/SHA checks with exact3513-member
coverage including the manifest. Target folder:
交付/MLWR_小参数与自举_ac25f4f_20261020.
The4lossless data ZIPs plus the main report/source ZIP total1,825,353,512 bytes.
Original shard metadata and a mapping/helper reconstruct all564 original members
without duplicating large outputs. Source snapshot is09d0257; do not mutate the
frozen package. The explicitly authorized unredacted import is complete.
Combined210-character title failed to save; five separate forms each use their
one complete attachment filename and an empty body. All5 outbox entries were
confirmed as awaiting the exchange administrator; final-recipient receipt is not
yet confirmed. All server filenames and exact byte counts match the originals.
The main ZIP additionally passed roundtrip download SHA256 verification; the4
raw-data ZIPs were not downloaded back. This distinction is recorded in the
local receipt, alongside recipient identity, application numbers, and filenames:
交付/MLWR_小参数与自举_ac25f4f_20261020_导入回执.html (and JSON).
The dedicated browser space was finished once and confirmed fully closed,
with no unmanaged user pages affected. Detailed recovery state is local only:
.local/bootstrap-20261020/sjz-latest-state.json. Do not reopen that closed space
or resend any of the5 confirmed forms. Implementation, qualification, artifact
verification, and this delivery are complete; the research limits above remain.
Draft PR1 is created and attached; do not merge without authorization:
https://github.com/leemaple/mlwralg/pull/1.
