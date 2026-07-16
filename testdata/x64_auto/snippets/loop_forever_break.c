/* Infinite loop (for(;;)) with two conditional early returns instead of a
 * counted exit -- probes how Ghidra/Gosleigh choose between `while (true)`,
 * `do { } while (true)`, and a synthesized for-loop when there is no natural
 * loop-exit condition to hoist into the loop header. */
long loop_forever_break(long *arr, long n, long target) {
	long i = 0;
	for (;;) {
		if (i >= n) {
			return -1;
		}
		if (arr[i] == target) {
			return i;
		}
		i++;
	}
}
