/* Byte-by-byte copy loop (memcpy shape, hand-written) -- probes whether
 * Gosleigh's output matches a plain indexed copy loop or diverges on the
 * const-qualified source pointer. */
void memcpy_style(char *dst, const char *src, long n) {
	for (long i = 0; i < n; i++) {
		dst[i] = src[i];
	}
}
