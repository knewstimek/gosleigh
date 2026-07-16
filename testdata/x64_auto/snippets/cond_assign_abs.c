/* Simple conditional reassignment (abs-shape: if negative, negate) -- a
 * textbook CMOV candidate; probes whether Gosleigh matches Ghidra's choice
 * between an if-branch and a synthesized conditional-move expression. */
long cond_assign_abs(long x) {
	long r = x;
	if (r < 0) {
		r = -r;
	}
	return r;
}
