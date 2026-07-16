/* Double-pointer walk with pointer increment -- expected PTR/TEMP: mirrors
 * x64_corpus2's sum_via_pp gap (raw '* 8' pointer scale left unfolded, and
 * an extra propagated temp for the loop-carried pointer). */
long sum_pp_walk(long **rows, long n) {
	long s = 0;
	long **p = rows;
	long **e = rows + n;
	while (p < e) {
		s += **p;
		p++;
	}
	return s;
}
