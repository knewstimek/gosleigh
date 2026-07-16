/* Brian Kernighan bit-count loop (x &= x-1) -- a while-loop whose exit
 * condition is "value became zero" rather than a counted index, a shape
 * not covered elsewhere in this corpus. */
int popcount_loop(unsigned long x) {
	int count = 0;
	while (x != 0) {
		x &= x - 1;
		count++;
	}
	return count;
}
