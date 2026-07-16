/* Reverse (descending) array traversal -- induction variable starts at
 * n-1 and counts down to 0, the mirror image of sum_array's ascending
 * walk. */
long array_reverse_sum(long *arr, long n) {
	long total = 0;
	for (long i = n - 1; i >= 0; i--) {
		total += arr[i];
	}
	return total;
}
