/* Nested while loops (vs. corpus #1's grid_score, which nests for-loops)
 * over a flattened 2D buffer -- same arithmetic shape as grid_score but
 * with the induction variables declared/incremented inside the loop body
 * instead of a for-header, which may hit a different structuring path. */
long nested_while_matrix(long *m, long rows, long cols) {
	long i = 0;
	long total = 0;
	while (i < rows) {
		long j = 0;
		while (j < cols) {
			total += m[i * cols + j];
			j++;
		}
		i++;
	}
	return total;
}
