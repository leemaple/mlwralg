# User-authorized implementation specification

Baseline: c6f7721e48d95f74dfbf1fdc03f9f1dfcc41baf5, the existing delivered compact
MLWR code. The frozen earlier reports and packages must remain intact.

1. Prioritize smaller parameters, more consecutive ciphertext multiplications and
lower total evaluation time. Keep the requested 128-classic table and default
maximum complex error 2^-20. Do not claim a proof of modified MLWR security.
2. Study the user's four translated papers (P01/P02/P03/P05); select compatible
advantages. P01/P05 are versions of the same work. Do not claim unsupported LCR,
OverModRaise, ring switches, sparse secrets or theoretical gains as implemented.
3. Provide true public-evaluation-key bootstrapping. No secret key, decryption or
re-encryption is accepted by Refresh. Restore real levels, continue multiplication,
and complete at least two refresh cycles. Test all N/2 slots in repeated layout.
4. Expose parameters via config/CLI, document code locations and reproduction.
Reject unsafe modulus budgets and mismatched keys, bases, roots, layouts and levels.
Include all actual public QP/T moduli in the table check.
5. Preserve failures; require correctness before performance claims. Independent
high-precision plaintext verification, multiple fresh keys, and exact source/binary
identities are required for admitted measurements. Diagnostic and qualification
runs have separate directories and labels.
6. Report tensor, relinearization, rescale, refresh phases, setup/keygen and complete
circuit times. Count folding, trace projection and its scale normalization. Compare
same-machine, same-workload results; label alternative HYBRID multiplication backend.
7. Deliver readable Chinese overview, parameter guide, source guide and raw evidence.
Retain all 60 requested l2 × k2/3 × N4096/8192/16384 × depth1..10 outcomes,
including rejections. New bootstrap parameters form a separate explicitly scoped grid.
8. Existing authorization covers GitHub tests/push, web ChatGPT Pro review and eventual
unredacted delivery to 徐温菊 through SJZ. Do not resend the previous archive.
