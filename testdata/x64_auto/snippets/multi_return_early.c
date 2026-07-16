/* Three independent early-return conditions inside one loop (vs.
 * corpus2's parse_steps, which funnels all failures through one goto
 * label) -- each condition returns a distinct constant directly. */
long multi_return_early(long *arr, long n) {
	for (long i = 0; i < n; i++) {
		if (arr[i] < 0) {
			return -1;
		}
		if (arr[i] == 0) {
			return 0;
		}
		if (arr[i] > 1000) {
			return 1;
		}
	}
	return 2;
}
