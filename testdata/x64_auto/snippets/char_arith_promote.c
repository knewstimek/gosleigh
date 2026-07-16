/* char + char with the usual integer promotion to int, then truncated back
 * into a char before being promoted again on return -- probes narrow-type
 * arithmetic distinct from this corpus's int/long-only functions. */
int char_arith_promote(char a, char b) {
	char c = a + b;
	return (int)c * 2;
}
