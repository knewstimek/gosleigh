/* True 2D array indexing (declared `long[][4]`, not a manually flattened
 * pointer) -- MSVC lowers m[i][j] to i*4+j address arithmetic, so this
 * checks whether Gosleigh's output re-collapses that back into [i][j]-style
 * indexing or leaves the raw multiply/add visible (PTR-style gap). */
long array_2d_sum(long m[][4], long rows) {
	long total = 0;
	for (long i = 0; i < rows; i++) {
		for (long j = 0; j < 4; j++) {
			total += m[i][j];
		}
	}
	return total;
}
