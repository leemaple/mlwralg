# Diagnostic and qualification plan

All initial runs are engineering diagnostics, not paper performance results. Preserve
their configurations, stdout/stderr and exit status. Freeze a separate formal matrix
only after focused implementation review and CI succeed.

1. Parameter preflight with actual primes/full public moduli, N=4096/8192/16384/32768/
65536/131072, requested table=128, and adjustable scales, first-prime bits, slots,
level budgets and usable levels. No HEStd_NotSet fallback.
2. Bridge sign, exact modulus/root, key tag, level, scale, shape and context tests.
3. True bootstrap on bounded complex slot inputs, with fresh-key repetitions. Compare
before/after plaintext, require increased levels, then compute after refresh. Include
two refresh cycles and a nontrivial bounded circuit to avoid vanishing-to-zero tests.
4. Paper-specific transform/rounding identities and prerequisite failures; a planner
prediction or literature result is never reported as a measured optimization.
5. Compact parameter search preserves all candidates, with 20-bit default and explicitly
named alternative precision families. A pilot that fails stays failed; qualification
uses independent keys and cannot overwrite pilots.

CPU budget: at most four local build jobs, one local heavy diagnostic at a time.
Prefer GitHub for multi-case long experiments. No individual diagnostic should run
unbounded; record timeouts as outcomes. Do not rerun a fresh key merely to hide a
precision failure. Stage timings exclude package/build/queue time and retain samples.
