/* Chained min AND max across four arguments (vs. corpus #1's max3, which
 * only chains max) -- two independent running extrema updated in the same
 * loop-free straight-line sequence of ifs. */
long minmax_chain4(long a, long b, long c, long d) {
	long mn;
	long mx;
	mn = a;
	if (b < mn) mn = b;
	if (c < mn) mn = c;
	if (d < mn) mn = d;
	mx = a;
	if (b > mx) mx = b;
	if (c > mx) mx = c;
	if (d > mx) mx = d;
	return mx - mn;
}
