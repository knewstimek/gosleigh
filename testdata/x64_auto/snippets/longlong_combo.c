/* Genuine 64-bit (long long, not Windows' 32-bit `long`) arithmetic mixing
 * multiply, shift, and subtract -- this corpus otherwise only exercises
 * `long`, which MSVC treats as 32-bit on x64/LLP64. */
long long longlong_combo(long long a, long long b, long long c) {
	long long t = (a * b) + (c << 3);
	t -= (a >> 2);
	return t;
}
