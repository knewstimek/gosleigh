/* NUL-terminated scan (strlen shape, hand-written so MSVC /Od has no CRT
 * intrinsic to substitute) -- loop exit is a memory-read comparison against
 * 0, not a counted index. */
long strlen_style(const char *s) {
	long len = 0;
	while (s[len] != 0) {
		len++;
	}
	return len;
}
