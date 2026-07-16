/* Dense switch with a non-zero base (10..17) -- MSVC should still emit a
 * jump table but with an extra subtract-base step before the table index,
 * unlike corpus #1's classify() which starts at 0. */
long switch_dense(int x) {
	switch (x) {
	case 10: return 100;
	case 11: return 101;
	case 12: return 102;
	case 13: return 103;
	case 14: return 104;
	case 15: return 105;
	case 16: return 106;
	case 17: return 107;
	default: return -1;
	}
}
