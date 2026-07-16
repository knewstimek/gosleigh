/* Two-pointer in-place reversal (converging lo/hi indices with a
 * swap-via-temp) -- combines reverse traversal with a paired-index loop
 * exit condition (lo < hi) instead of a single counted induction variable. */
void reverse_bytes_inplace(char *buf, long n) {
	long lo = 0;
	long hi = n - 1;
	while (lo < hi) {
		char t = buf[lo];
		buf[lo] = buf[hi];
		buf[hi] = t;
		lo++;
		hi--;
	}
}
