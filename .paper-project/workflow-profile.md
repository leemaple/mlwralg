# Scope and operating profile

Input: current independently implemented MLWR standard/compact schemes, fixed OpenFHE
1.6.1 b59e1f2, previous parameter results, and four user-provided CKKS texts.
Output: runnable source, adjustable configurations and parameter guide, verified
correctness/stage timing/raw data, clear Chinese HTML/PDF report and complete archive.
The task is implementation and feasibility closure, not a new publication submission.

Preserve the 128-classic parameter-table check and default maximum complex error
2^-20. Distinguish the RLWE parameter table from a proof for the modified MLWR scheme.
Expose other requested precision levels explicitly; do not lower the default silently.
Measure actual post-bootstrap levels and continuation, not just configured depth.
Evaluation APIs must not accept secret keys, decrypted values, or cleartext refreshes.
Cross-scheme evaluation keys add assumptions that need explicit disclosure.

User has authorized local implementation, GitHub pushes/tests, ChatGPT Pro technical
collaboration, and eventual original-byte SJZ delivery to 徐温菊. No authorization is
inferred for paid compute, publication, changing security targets, or using arbitrary
external accounts. Prefer bounded local diagnostic runs and exact-commit Linux CI.
Use research background work and an independent focused review where the installed
skills prescribe them. Do not repeat successful older experiments without new need.

Flexible choices: implementation seams, parameter-search ordering, experiment sizes,
and compatible optimization subsets. Hard boundaries: correctness, full public-key
modulus accounting, source identity, negative-result preservation, and honest coverage.
If an optimization's prerequisites cannot be met, preserve the reason and continue
other independent implementation and experiments instead of presenting a fake switch.

Success example: a true refresh increases available levels, maintains the selected
precision in multiple fresh-key tests, and permits a longer evaluated circuit; report
its actual N, k/l, slots, scales, public Q/P, timings, and reproducible invocation.
