/* x86-64 breadth corpus #2 for Gosleigh golden generation (discovery).
 *
 * Compiled with MSVC cl /c /Od (Windows x64 ABI: RCX,RDX,R8,R9 integer args).
 * Targets C structures NOT covered by testdata/x64_corpus/corpus.c:
 * do-while + break/continue, nested loop + conditional break, short-circuit
 * && || chains, nested ternary, small-struct value pass/return (register
 * packing), struct-array field update, pointer arithmetic + double pointer,
 * signed/unsigned magic-number division, direct function call (>4 args, callee
 * included), goto error handling, and two probes (float, 64-bit high multiply).
 *
 * Most functions are self-contained (no external calls, no globals) so the .obj
 * .text bytes are position-independent -- the bytes Ghidra analyzes are the
 * bytes fed to the Gosleigh tree. Exceptions on purpose (discovery):
 *   - caller() calls helper_sum() (same .obj)  -> intra-.text REL32 relocation.
 *   - faverage() loads the float constant 3.0  -> RIP-relative .rdata load.
 * These probe the loader/reloc + call-target + FP paths and may MISMATCH; that
 * is the point of a discovery corpus. Goldens (bytes + decompiled C) come from
 * Ghidra 12 headless via GenGoldens.java. See README.md.
 */

/* 1. do-while loop with both continue and break. */
long dowhile_scan(long *p, long n) {
	long s = 0;
	long i = 0;
	do {
		long v = p[i];
		i++;
		if (v < 0) {
			continue;
		}
		if (v == 999) {
			break;
		}
		s += v;
	} while (i < n);
	return s;
}

/* 2. nested loop with an early conditional break out of both levels. */
long find_pair(long *a, long n, long target) {
	for (long i = 0; i < n; i++) {
		for (long j = i + 1; j < n; j++) {
			if (a[i] + a[j] == target) {
				return i * 100 + j;
			}
		}
	}
	return -1;
}

/* 3. short-circuit condition chain mixing && and || across four args. */
long gate(long a, long b, long c, long d) {
	if ((a > 0 && b > 0) || (c < 0 && d != 0)) {
		return a + b;
	}
	return c - d;
}

/* 4. nested ternary operator. */
long clamp3(long x, long lo, long hi) {
	return x < lo ? lo : (x > hi ? hi : x);
}

/* 5. small struct (8 bytes) value pass and return -- register packing. */
typedef struct {
	int x;
	int y;
} Point;

Point add_pt(Point a, Point b) {
	Point r;
	r.x = a.x + b.x;
	r.y = a.y + b.y;
	return r;
}

/* 6. struct-array indexing with in-place field update. */
typedef struct {
	int id;
	int score;
} Rec;

int bump_scores(Rec *arr, int n, int delta) {
	int total = 0;
	for (int i = 0; i < n; i++) {
		arr[i].score += delta;
		total += arr[i].score;
	}
	return total;
}

/* 7. pointer arithmetic: double-pointer walk with pointer increment. */
long sum_via_pp(long **rows, long nrows) {
	long s = 0;
	long **p = rows;
	long **e = rows + nrows;
	while (p < e) {
		s += **p;
		p++;
	}
	return s;
}

/* 8. signed and unsigned division by constants (magic-number division). */
long divmix(long a, unsigned long b) {
	long q = a / 7;
	unsigned long r = b % 9u;
	return q + (long)r;
}

/* 9a. callee for the direct-call probe (5 args -> 5th passed on the stack). */
static int helper_sum(int a, int b, int c, int d, int e) {
	return a + b + c - d * e;
}

/* 9b. direct function call, callee in the same object. */
int caller(int a, int b, int c, int d, int e) {
	return helper_sum(a, b, c, d, e) + helper_sum(e, d, c, b, a);
}

/* 10. goto-based error handling with a shared failure label. */
int parse_steps(int *in, int n) {
	int acc = 0;
	int i = 0;
	while (i < n) {
		if (in[i] < 0) {
			goto fail;
		}
		if (in[i] > 1000) {
			goto fail;
		}
		acc += in[i];
		i++;
	}
	return acc;
fail:
	return -1;
}

/* 11. probe: simple float arithmetic (xmm + constant pool). */
float faverage(float a, float b, float c) {
	return (a + b + c) / 3.0f;
}

/* 12. probe: 64x64 -> high 64 multiply (128-bit intermediate via 32-bit split). */
unsigned long long umulhi(unsigned long long a, unsigned long long b) {
	unsigned long long alo = a & 0xffffffffULL;
	unsigned long long ahi = a >> 32;
	unsigned long long blo = b & 0xffffffffULL;
	unsigned long long bhi = b >> 32;
	unsigned long long cross = ahi * blo + (alo * blo >> 32);
	unsigned long long carry = (cross & 0xffffffffULL) + alo * bhi;
	return ahi * bhi + (cross >> 32) + (carry >> 32);
}
