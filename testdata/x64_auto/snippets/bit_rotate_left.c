/* Left rotate via shift+or (x << s | x >> (32-s)) -- checks whether
 * Gosleigh recognizes/preserves the rotate idiom or shows raw shift ops. */
unsigned long bit_rotate_left(unsigned long x, int shift) {
	return (x << shift) | (x >> (32 - shift));
}
