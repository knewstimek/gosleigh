/* Mask + shift field extraction (byte/nibble split and recombine) -- pure
 * bitwise, no arithmetic carries, to isolate mask/shift recovery from the
 * unrelated pointer-scale gap seen in sum_pp_walk/sum_via_pp. */
unsigned long bit_mask_shift_combo(unsigned long x) {
	unsigned long lo = x & 0xffu;
	unsigned long mid = (x >> 8) & 0xffu;
	unsigned long hi = (x >> 16) & 0xffffu;
	return (hi << 16) | (mid << 8) | lo;
}
