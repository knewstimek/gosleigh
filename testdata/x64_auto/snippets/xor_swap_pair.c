/* XOR swap (no temp variable) through two out-parameters -- probes whether
 * Gosleigh's expression recovery re-derives a clean 3-XOR sequence or
 * leaves it as opaque temp shuffling. */
void xor_swap_pair(long *a, long *b) {
	*a ^= *b;
	*b ^= *a;
	*a ^= *b;
}
