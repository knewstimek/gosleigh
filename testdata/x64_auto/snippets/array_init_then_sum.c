/* Local fixed-size array initialized in one loop, then summed in a second
 * loop over the same range -- probes stack-array liveness/init recovery
 * (distinct from sum_loop/sum_array, which only ever read a caller-owned
 * array). */
long array_init_then_sum(long n) {
	long buf[16];
	long i;
	long total;
	if (n > 16) {
		n = 16;
	}
	for (i = 0; i < n; i++) {
		buf[i] = i * i;
	}
	total = 0;
	for (i = 0; i < n; i++) {
		total += buf[i];
	}
	return total;
}
