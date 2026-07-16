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
