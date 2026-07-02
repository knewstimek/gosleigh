/* x86-64 breadth corpus (extension) for Gosleigh gap discovery.
 *
 * Compiled with MSVC cl /c /Od (Windows x64 ABI: RCX,RDX,R8,R9 integer args).
 * These functions cover patterns absent from the base corpus:
 *   - struct field access through a pointer (multi-offset deref)
 *   - nested/2D array indexing (row*cols+col address arithmetic)
 *   - dense switch (candidate jump-table lowering)
 *
 * Self-contained where possible so the .text bytes are relocation-free and can
 * be fed at base 0 to the Gosleigh tree exactly as Ghidra sees them. The dense
 * switch may emit a .rdata jump table + relocation -- that itself is a mapped
 * gap for the single-section harness.
 */

struct Point {
	long x;
	long y;
};

/* 1. struct field access through a pointer (offsets 0 and 8). */
long dist_sq(struct Point *p) {
	return p->x * p->x + p->y * p->y;
}

/* 2. nested/2D array indexing: m[i*cols + j] summed over a rows x cols grid. */
long sum2d(long *m, long rows, long cols) {
	long s = 0;
	for (long i = 0; i < rows; i++) {
		for (long j = 0; j < cols; j++) {
			s += m[i * cols + j];
		}
	}
	return s;
}

/* 3. dense switch (0..7) -- candidate jump-table lowering under MSVC /Od. */
long dispatch(long x) {
	switch (x) {
	case 0: return 11;
	case 1: return 22;
	case 2: return 33;
	case 3: return 44;
	case 4: return 55;
	case 5: return 66;
	case 6: return 77;
	case 7: return 88;
	default: return -1;
	}
}
