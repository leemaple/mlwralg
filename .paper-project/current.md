# Current checkpoint — 2026-10-20

Scope: extend the delivered MLWR implementation with real, evaluator-only bootstrapping,
study the four supplied CKKS texts, and expand reproducible parameter choices.
Branch: codex/bootstrap-four-papers. Starting source: c6f7721e48d95f74dfbf1fdc03f9f1dfcc41baf5.

The previous package and its 60 observations are frozen and remain unchanged.
It was submitted unredacted to 徐温菊 (17808), W[2026]109522, administrator pending.

Current gate: implementation review and regression tests; no formal result admitted.
The four texts are p01, p02, p03, p05 in the local 徐博论文翻译及整理 project.
p01 and p05 are two versions of one LCR/AKS study, not independent gains.

User priority clarified: smaller parameters, more consecutive ciphertext multiplications,
and lower complete-circuit elapsed time at the same 128 table and 20-bit target.

Implemented but not qualified: same-ring MLWR↔RLWE public evaluation-key bridge;
compact symmetric relinearization (k² -> k(k+1)/2 products); fractional compact prime
targets; common balanced gadget switching, also usable by the standard module engine.
The native bootstrap at scale42/45 failed; those diagnostics remain preserved.
At scale55 with two-iteration correction, public repeated-slot trace removes the
out-of-subring noise. Physical integer multiplication plus one actual rescale brings
the trace scale back near OpenFHE's scheduled scale. Merely recording trace scale
passed single refresh but failed subsequent native multiplication/refresh; both
counterexamples are retained. Factor alignment now projects its exact basis while
preserving its actual scale, avoiding native unequal-level scale assumptions.
A separate pinned P03 small repeated-slot CtS/StC port is built and tested.
The original .deps/openfhe-src and previous delivery packages are untouched.

N8192 depth5 scale27/first48/divisor16/P17 passed one original key but failed a
subsequent 3-key symmetric diagnostic for k2 and k3 (errors just above 2^-20).
Both outcomes are retained in .local/bootstrap-20261020. Do not advertise depth5
as qualified. Fractional27.5 passed k2 but failed k3. The newer packed-T profile
27.83/first46/divisor16/P17/symmetric1 passed both k2/k3 with 3 keys × 3 message
families and independent verification (worst 5.76e-7 and 4.84e-7); still diagnostics.

N65536 scale55/first56/usable8/HYBRID5/Pmodule60 has completed 12 encrypted
bounded-factor multiplications and 3 actual refreshes, native and P03, errors
2.10e-8 and 2.28e-8. Independent 140-digit oracle checked 557056 full slots each.
The fast continuation backend is explicitly folded_rlwe_hybrid, not module Mult.
Original module-gadget continuation remains available but key generation is slow.
These results do not demonstrate N8192 bootstrapping or an LCR/OverModRaise port.

Next gate: native and P03 numerical diagnostics, fractional compact qualification,
focused tests and independent code review. N=8192 must not bypass its full public-modulus budget. A larger-ring
bootstrap is not a refresh of an 8192-ring ciphertext without a separate ring switch.

See workflow-profile.md and experiments.md. Research notes are written to
docs/bootstrap-paper-research.md. Do not label a baseline, planner, simulated refresh,
client decrypt/re-encrypt, or a no-op EvalBootstrap result as a successful fusion.
