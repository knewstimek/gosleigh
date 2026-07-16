/* short * short + 1, truncated back into a short before the implicit
 * widen-to-int on return -- same idea as char_arith_promote at the next
 * narrow-type size up. */
int short_arith_trunc(short a, short b) {
	short c = (short)(a * b + 1);
	return c;
}
