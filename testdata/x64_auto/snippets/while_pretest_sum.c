/* Plain while loop with condition tested before the body (vs. sum_loop's
 * for-loop) -- checks whether Gosleigh's for/while printer-detector agrees
 * with Ghidra on this AST shape even though the machine code is the same
 * loop-test-first pattern already known MATCH via sum_loop. */
long while_pretest_sum(long *arr, long n) {
	long i = 0;
	long total = 0;
	while (i < n) {
		total += arr[i];
		i++;
	}
	return total;
}
