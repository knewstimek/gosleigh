/* Sparse switch (values 1, 50, 999) -- values too spread out for a jump
 * table, so MSVC should compile this as a compare chain instead. */
long switch_sparse(int x) {
	switch (x) {
	case 1: return 111;
	case 50: return 222;
	case 999: return 333;
	default: return -1;
	}
}
