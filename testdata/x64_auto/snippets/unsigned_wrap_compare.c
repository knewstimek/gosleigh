/* Unsigned subtraction with an explicit wraparound guard (diff > a implies
 * b > a underflowed) -- probes unsigned compare recovery distinct from the
 * signed comparisons used everywhere else in this corpus. */
unsigned int unsigned_wrap_compare(unsigned int a, unsigned int b) {
	unsigned int diff = a - b;
	if (diff > a) {
		return 0;
	}
	return diff;
}
