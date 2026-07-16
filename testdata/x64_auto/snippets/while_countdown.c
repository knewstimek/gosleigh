/* Countdown while loop with a non-unit decrement (step 2, not 1) -- probes
 * whether the induction-variable step size affects loop-header recovery. */
long while_countdown(long n) {
	long total = 0;
	while (n > 0) {
		total += n;
		n -= 2;
	}
	return total;
}
