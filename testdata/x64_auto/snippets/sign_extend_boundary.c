/* Truncate a 32-bit value down to char and short, then sign-extend each
 * back up to long -- probes the sign-extension boundary at the narrow-type
 * truncation point (CONCAT/SUBPIECE-style ops in the golden). */
long sign_extend_boundary(int x) {
	char c = (char)x;
	short s = (short)x;
	return (long)c + (long)s;
}
