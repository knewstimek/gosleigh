/* x86-64 auto corpus for tools/goldengap/goldengap.py.
 *
 * Populated incrementally via `goldengap.py add <name> <file_or_code>`.
 * Compiled with MSVC cl /c /Od /GS- (Windows x64 ABI). Pipeline cloned from
 * testdata/x64_corpus2 (build.py/run_ghidra.py/GenGoldens.java unchanged,
 * self-relative to this directory).
 */


/* added via goldengap add: sum_loop */
/* Simple for-loop accumulation over an array -- expected MATCH: this shape
 * (single induction variable, no early exit, no pointer-of-pointer) already
 * matches corpus #1's sum_array/sum_to_n patterns, which are known 8/8. */
long sum_loop(long *arr, long n) {
	long total = 0;
	for (long i = 0; i < n; i++) {
		total += arr[i];
	}
	return total;
}

/* added via goldengap add: dowhile_count */
/* do-while loop, no continue/break -- expected STRUCT: Gosleigh's block
 * structuring does not yet turn a do-while back-edge into `do { } while`,
 * so it should show up as a dangling goto / missing do-while keyword. */
int dowhile_count(int *p, int n) {
	int count = 0;
	int i = 0;
	do {
		if (p[i] > 0) {
			count++;
		}
		i++;
	} while (i < n);
	return count;
}

/* added via goldengap add: sum_pp_walk */
/* Double-pointer walk with pointer increment -- expected PTR/TEMP: mirrors
 * x64_corpus2's sum_via_pp gap (raw '* 8' pointer scale left unfolded, and
 * an extra propagated temp for the loop-carried pointer). */
long sum_pp_walk(long **rows, long n) {
	long s = 0;
	long **p = rows;
	long **e = rows + n;
	while (p < e) {
		s += **p;
		p++;
	}
	return s;
}
