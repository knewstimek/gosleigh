/* Reuses parameter `a` itself as the accumulator (reassigned three times,
 * no separate local ever declared) -- directly probes the param_2-reuse
 * Symbol-merge path implicated in the op_switch uVar1 fix (see
 * docs/CHANGELOG.md 2026-07-17). */
long param_reuse_accum(long a, long b) {
	a = a + b;
	a = a * 2;
	a = a - b;
	return a;
}
