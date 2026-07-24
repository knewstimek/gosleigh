/* x86-64 auto corpus for tools/goldengap/goldengap.py.
 *
 * Populated incrementally via `goldengap.py add <name> <file_or_code>`.
 * Compiled with MSVC cl /c /Od /GS- (Windows x64 ABI). Pipeline cloned from
 * testdata/x64_corpus2 (build.py/run_ghidra.py/GenGoldens.java unchanged,
 * self-relative to this directory).
 */


/* added via goldengap add: sum_loop */
/* Simple for-loop accumulation over an array -- expected MATCH: this shape
 * (single induction variable, no early exit, no pointer-of-pointer) already
 * matches corpus #1's sum_array/sum_to_n patterns, which are known 8/8. */
long sum_loop(long *arr, long n) {
	long total = 0;
	for (long i = 0; i < n; i++) {
		total += arr[i];
	}
	return total;
}

/* added via goldengap add: dowhile_count */
/* do-while loop, no continue/break -- expected STRUCT: Gosleigh's block
 * structuring does not yet turn a do-while back-edge into `do { } while`,
 * so it should show up as a dangling goto / missing do-while keyword. */
int dowhile_count(int *p, int n) {
	int count = 0;
	int i = 0;
	do {
		if (p[i] > 0) {
			count++;
		}
		i++;
	} while (i < n);
	return count;
}

/* added via goldengap add: sum_pp_walk */
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

/* added via goldengap add: while_pretest_sum */
/* Plain while loop with condition tested before the body (vs. sum_loop's
 * for-loop) -- checks whether Gosleigh's for/while printer-detector agrees
 * with Ghidra on this AST shape even though the machine code is the same
 * loop-test-first pattern already known MATCH via sum_loop. */
long while_pretest_sum(long *arr, long n) {
	long i = 0;
	long total = 0;
	while (i < n) {
		total += arr[i];
		i++;
	}
	return total;
}

/* added via goldengap add: loop_forever_break */
/* Infinite loop (for(;;)) with two conditional early returns instead of a
 * counted exit -- probes how Ghidra/Gosleigh choose between `while (true)`,
 * `do { } while (true)`, and a synthesized for-loop when there is no natural
 * loop-exit condition to hoist into the loop header. */
long loop_forever_break(long *arr, long n, long target) {
	long i = 0;
	for (;;) {
		if (i >= n) {
			return -1;
		}
		if (arr[i] == target) {
			return i;
		}
		i++;
	}
}

/* added via goldengap add: nested_while_matrix */
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

/* added via goldengap add: while_countdown */
/* Countdown while loop with a non-unit decrement (step 2, not 1) -- probes
 * whether the induction-variable step size affects loop-header recovery. */
long while_countdown(long n) {
	long total = 0;
	while (n > 0) {
		total += n;
		n -= 2;
	}
	return total;
}

/* added via goldengap add: switch_dense */
/* Dense switch with a non-zero base (10..17) -- MSVC should still emit a
 * jump table but with an extra subtract-base step before the table index,
 * unlike corpus #1's classify() which starts at 0. */
long switch_dense(int x) {
	switch (x) {
	case 10: return 100;
	case 11: return 101;
	case 12: return 102;
	case 13: return 103;
	case 14: return 104;
	case 15: return 105;
	case 16: return 106;
	case 17: return 107;
	default: return -1;
	}
}

/* added via goldengap add: switch_sparse */
/* Sparse switch (values 1, 50, 999) -- values too spread out for a jump
 * table, so MSVC should compile this as a compare chain instead. */
long switch_sparse(int x) {
	switch (x) {
	case 1: return 111;
	case 50: return 222;
	case 999: return 333;
	default: return -1;
	}
}

/* added via goldengap add: switch_no_default */
/* Switch with no default clause -- the fall-through-to-nothing path leaves
 * the result at its initializer when no case matches. */
int switch_no_default(int x) {
	int r = -1;
	switch (x) {
	case 1: r = 10; break;
	case 2: r = 20; break;
	case 3: r = 30; break;
	}
	return r;
}

/* added via goldengap add: switch_fallthrough */
/* Switch with an intentional case fall-through (case 1 and case 2 share
 * one body) -- probes whether Gosleigh preserves the shared-case grouping
 * or expands it into duplicated/gotoed blocks. */
int switch_fallthrough(int x) {
	int r;
	switch (x) {
	case 1:
	case 2:
		r = 100;
		break;
	case 3:
		r = 200;
		break;
	default:
		r = -1;
	}
	return r;
}

/* added via goldengap add: array_2d_sum */
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

/* added via goldengap add: array_init_then_sum */
/* Local fixed-size array initialized in one loop, then summed in a second
 * loop over the same range -- probes stack-array liveness/init recovery
 * (distinct from sum_loop/sum_array, which only ever read a caller-owned
 * array). */
long array_init_then_sum(long n) {
	long buf[16];
	long i;
	long total;
	if (n > 16) {
		n = 16;
	}
	for (i = 0; i < n; i++) {
		buf[i] = i * i;
	}
	total = 0;
	for (i = 0; i < n; i++) {
		total += buf[i];
	}
	return total;
}

/* added via goldengap add: array_reverse_sum */
/* Reverse (descending) array traversal -- induction variable starts at
 * n-1 and counts down to 0, the mirror image of sum_array's ascending
 * walk. */
long array_reverse_sum(long *arr, long n) {
	long total = 0;
	for (long i = n - 1; i >= 0; i--) {
		total += arr[i];
	}
	return total;
}

/* added via goldengap add: reverse_bytes_inplace */
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

/* added via goldengap add: bit_mask_shift_combo */
/* Mask + shift field extraction (byte/nibble split and recombine) -- pure
 * bitwise, no arithmetic carries, to isolate mask/shift recovery from the
 * unrelated pointer-scale gap seen in sum_pp_walk/sum_via_pp. */
unsigned long bit_mask_shift_combo(unsigned long x) {
	unsigned long lo = x & 0xffu;
	unsigned long mid = (x >> 8) & 0xffu;
	unsigned long hi = (x >> 16) & 0xffffu;
	return (hi << 16) | (mid << 8) | lo;
}

/* added via goldengap add: popcount_loop */
/* Brian Kernighan bit-count loop (x &= x-1) -- a while-loop whose exit
 * condition is "value became zero" rather than a counted index, a shape
 * not covered elsewhere in this corpus. */
int popcount_loop(unsigned long x) {
	int count = 0;
	while (x != 0) {
		x &= x - 1;
		count++;
	}
	return count;
}

/* added via goldengap add: xor_swap_pair */
/* XOR swap (no temp variable) through two out-parameters -- probes whether
 * Gosleigh's expression recovery re-derives a clean 3-XOR sequence or
 * leaves it as opaque temp shuffling. */
void xor_swap_pair(long *a, long *b) {
	*a ^= *b;
	*b ^= *a;
	*a ^= *b;
}

/* added via goldengap add: bit_rotate_left */
/* Left rotate via shift+or (x << s | x >> (32-s)) -- checks whether
 * Gosleigh recognizes/preserves the rotate idiom or shows raw shift ops. */
unsigned long bit_rotate_left(unsigned long x, int shift) {
	return (x << shift) | (x >> (32 - shift));
}

/* added via goldengap add: unsigned_wrap_compare */
/* Unsigned subtraction with an explicit wraparound guard (diff > a implies
 * b > a underflowed) -- probes unsigned compare recovery distinct from the
 * signed comparisons used everywhere else in this corpus. */
unsigned int unsigned_wrap_compare(unsigned int a, unsigned int b) {
	unsigned int diff = a - b;
	if (diff > a) {
		return 0;
	}
	return diff;
}

/* added via goldengap add: longlong_combo */
/* Genuine 64-bit (long long, not Windows' 32-bit `long`) arithmetic mixing
 * multiply, shift, and subtract -- this corpus otherwise only exercises
 * `long`, which MSVC treats as 32-bit on x64/LLP64. */
long long longlong_combo(long long a, long long b, long long c) {
	long long t = (a * b) + (c << 3);
	t -= (a >> 2);
	return t;
}

/* added via goldengap add: sign_extend_boundary */
/* Truncate a 32-bit value down to char and short, then sign-extend each
 * back up to long -- probes the sign-extension boundary at the narrow-type
 * truncation point (CONCAT/SUBPIECE-style ops in the golden). */
long sign_extend_boundary(int x) {
	char c = (char)x;
	short s = (short)x;
	return (long)c + (long)s;
}

/* added via goldengap add: char_arith_promote */
/* char + char with the usual integer promotion to int, then truncated back
 * into a char before being promoted again on return -- probes narrow-type
 * arithmetic distinct from this corpus's int/long-only functions. */
int char_arith_promote(char a, char b) {
	char c = a + b;
	return (int)c * 2;
}

/* added via goldengap add: short_arith_trunc */
/* short * short + 1, truncated back into a short before the implicit
 * widen-to-int on return -- same idea as char_arith_promote at the next
 * narrow-type size up. */
int short_arith_trunc(short a, short b) {
	short c = (short)(a * b + 1);
	return c;
}

/* added via goldengap add: cond_assign_abs */
/* Simple conditional reassignment (abs-shape: if negative, negate) -- a
 * textbook CMOV candidate; probes whether Gosleigh matches Ghidra's choice
 * between an if-branch and a synthesized conditional-move expression. */
long cond_assign_abs(long x) {
	long r = x;
	if (r < 0) {
		r = -r;
	}
	return r;
}

/* added via goldengap add: minmax_chain4 */
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

/* added via goldengap add: strlen_style */
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

/* added via goldengap add: memcpy_style */
/* Byte-by-byte copy loop (memcpy shape, hand-written) -- probes whether
 * Gosleigh's output matches a plain indexed copy loop or diverges on the
 * const-qualified source pointer. */
void memcpy_style(char *dst, const char *src, long n) {
	for (long i = 0; i < n; i++) {
		dst[i] = src[i];
	}
}

/* added via goldengap add: multi_return_early */
/* Three independent early-return conditions inside one loop (vs.
 * corpus2's parse_steps, which funnels all failures through one goto
 * label) -- each condition returns a distinct constant directly. */
long multi_return_early(long *arr, long n) {
	for (long i = 0; i < n; i++) {
		if (arr[i] < 0) {
			return -1;
		}
		if (arr[i] == 0) {
			return 0;
		}
		if (arr[i] > 1000) {
			return 1;
		}
	}
	return 2;
}

/* added via goldengap add: nested_if_ladder_grade */
/* Nested if-else-if ladder (grade classification) with a narrow (char)
 * return type -- straight-line comparisons, no loop, to isolate ladder
 * structuring from loop-recovery gaps. */
char nested_if_ladder_grade(int score) {
	if (score >= 90) {
		return 'A';
	} else if (score >= 80) {
		return 'B';
	} else if (score >= 70) {
		return 'C';
	} else if (score >= 60) {
		return 'D';
	} else {
		return 'F';
	}
}

/* added via goldengap add: param_reuse_accum */
/* Reuses parameter `a` itself as the accumulator (reassigned three times,
 * no separate local ever declared) -- directly probes the param_2-reuse
 * Symbol-merge path implicated in the op_switch uVar1 fix (see
 * docs/CHANGELOG.md 2026-07-17). */
long param_reuse_accum(long a, long b) {
	a = a + b;
	a = a * 2;
	a = a - b;
	return a;
}

/* added via goldengap add: swap_via_temp */
/* Classic swap via an explicit temp variable -- the "normal" counterpart
 * to xor_swap_pair's no-temp variant, same two out-parameters. */
void swap_via_temp(long *a, long *b) {
	long tmp = *a;
	*a = *b;
	*b = tmp;
}

/* added via goldengap add: probe_distribute */
long probe_distribute(long *arr, long i, long j) { return arr[(i + j) * 3]; }

/* probe: distribute -- pre-factored i*3 + j*3 (exercises AddTreeState reassoc /
 * distributeIntMultAdd; audit-map #1). Does the engine keep the factored form
 * or recombine to (i+j)*3? Compare to Ghidra ground truth. */
long probe_dist_factor(long *arr, long i, long j) {
	return arr[i * 3 + j * 3];
}

/* probe: distribute -- scaled sum plus an extra non-scaled term. */
long probe_dist_mixed(long *arr, long i, long j) {
	return arr[(i + j) * 3 + j];
}

/* --- self-contained divergence probes (no external symbols/globals) --- */

/* unsigned division by constant -> magic-number multiply (RuleDivOpt). */
unsigned probe_udiv(unsigned x) { return x / 7u; }

/* signed division by constant -> signed magic + sign correction. */
int probe_sdiv(int x) { return x / 7; }

/* signed modulo by constant. */
int probe_smod(int x) { return x % 10; }

/* select / max via ternary. */
int probe_ternary(int a, int b) { return a > b ? a : b; }

/* nested ternary clamp. */
int probe_clamp(int x) { return x < 0 ? 0 : (x > 100 ? 100 : x); }


/* short sign-extension into int arithmetic. */
int probe_sext(short s) { return s + 1; }

/* char array accumulation loop (byte load, sign extend). */
int probe_charsum(char *s, int n) {
	int t = 0;
	for (int i = 0; i < n; i++) t += s[i];
	return t;
}

/* --- session11 batch 2: type/shift/cast idioms (self-contained) --- */

unsigned probe_ushr(unsigned x) { return x >> 3; }
int probe_sshr(int x) { return x >> 3; }
long long probe_ll_shift(long long x) { return x << 40; }
long probe_ptrdiff(int *a, int *b) { return a - b; }
long long probe_widen(int x, int y) { return (long long)x * y; }
int probe_narrow(long long x) { return (int)x + 1; }
unsigned probe_mask(unsigned x) { return (x >> 4) & 0xF; }
int probe_3d(int *a, int i, int j, int k) { return a[i * 100 + j * 10 + k]; }

/* --- session11 batch 3: return-type / render stress (self-contained) --- */

unsigned probe_ret_and(unsigned a, unsigned b) { return a & b; }
unsigned probe_ret_not(unsigned x) { return ~x; }
long long probe_ret_wide(int a, int b) { return (long long)a + b; }

/* --- session11 batch 4: control-flow / pointer idioms (self-contained) --- */

int probe_early_return(int *a, int n) {
	for (int i = 0; i < n; i++) if (a[i] < 0) return i;
	return -1;
}
int probe_ptr2ptr(int **pp) { return **pp; }
int probe_continue_sum(int *a, int n) {
	int s = 0;
	for (int i = 0; i < n; i++) { if (a[i] == 0) continue; s += a[i]; }
	return s;
}
long long probe_mixed_sign(int a, unsigned b) { return (long long)a + b; }

/* --- session11 batch 5: constant / render stress (self-contained) --- */

int probe_negconst(int x) { return x + -5; }
unsigned probe_hexbig(unsigned x) { return x | 0xdeadbeef; }
long long probe_const64(long long x) { return x + 0x100000000LL; }
unsigned probe_shiftmask(unsigned x) { return (x << 8) | (x >> 24); }

/* --- session11 batch 6: return-of-memory shapes (validates LOAD-boundary fix) --- */

int probe_ret_deref(int *p) { return *p; }
int probe_ret_subscript(int *p) { return p[3]; }
int probe_ret_derefadd(int *p) { return *p + 1; }
long long probe_ret_load8(long long *p) { return *p; }

/* --- session11 batch 7: realistic multi-feature functions (self-contained) --- */

int probe_sum_pos(int *a, int n) {
	int s = 0;
	for (int i = 0; i < n; i++) if (a[i] > 0) s += a[i];
	return s;
}
int probe_strlen2(char *s) {
	int n = 0;
	while (s[n]) n++;
	return n;
}
int probe_count_bits(unsigned x) {
	int c = 0;
	while (x) { c += x & 1; x >>= 1; }
	return c;
}

/* --- session11 batch 8: return-width / narrow-type render stress --- */

short probe_ret_short(int x) { return (short)(x + 1); }
char probe_ret_char(int x) { return (char)(x + 1); }
long long probe_ret_ll(int x) { return (long long)x * 1000; }
unsigned short probe_ret_ushort(unsigned x) { return (unsigned short)(x >> 3); }

/* --- session11 batch 9: realistic algorithms (conditional-light) --- */

int probe_fib(int n) {
	int a = 0, b = 1;
	for (int i = 0; i < n; i++) { int t = a + b; a = b; b = t; }
	return a;
}
int probe_power(int base, int exp) {
	int r = 1;
	for (int i = 0; i < exp; i++) r *= base;
	return r;
}
int probe_stride_sum(int *a, int n, int k) {
	int s = 0;
	for (int i = 0; i < n; i += k) s += a[i];
	return s;
}
void probe_reverse_arr(int *a, int n) {
	for (int i = 0; i < n / 2; i++) { int t = a[i]; a[i] = a[n-1-i]; a[n-1-i] = t; }
}

/* --- session11 batch 10: string/byte operations (void-return, uncovered) --- */

void probe_bytecopy(char *d, char *s, int n) {
	for (int i = 0; i < n; i++) d[i] = s[i];
}
int probe_sum_bytes(unsigned char *p, int n) {
	int s = 0;
	for (int i = 0; i < n; i++) s += p[i];
	return s;
}

/* --- session11 batch 11: arithmetic-heavy (hash/poly/bit, MATCH-likely) --- */

int probe_hash31(char *p, int n) {
	int h = 0;
	for (int i = 0; i < n; i++) h = h * 31 + p[i];
	return h;
}
int probe_xor_reduce(int *a, int n) {
	int x = 0;
	for (int i = 0; i < n; i++) x ^= a[i];
	return x;
}
int probe_poly(int x) { return x * x * x + 2 * x * x + 3 * x + 4; }
unsigned probe_swap_nibbles(unsigned x) {
	return ((x & 0xf0f0f0f0) >> 4) | ((x & 0x0f0f0f0f) << 4);
}
int probe_running_prod(int *a, int n) {
	int p = 1;
	for (int i = 0; i < n; i++) p *= a[i];
	return p;
}

void probe_memset(char *p, int c, int n) {
	for (int i = 0; i < n; i++) p[i] = (char)c;
}

/* --- session11 batch 12: param materialization / byte-short param / store render --- */

int probe_short_add(short a, short b) { return a + b; }
void probe_write_through(int *p, int v) { *p = v; }
void probe_byte_store2(char *p, char c) { p[0] = c; p[1] = c; }
short probe_short_ident(short x) { return x; }



/* --- session11 batch 13: multi-return (ReturnSplit / structuring) --- */

int probe_sign(int x) {
	if (x > 0) return 1;
	if (x < 0) return -1;
	return 0;
}
int probe_first_neg(int *a, int n) {
	for (int i = 0; i < n; i++) if (a[i] < 0) return i;
	return -1;
}
int probe_classify(int x) {
	if (x < 10) return 0;
	if (x < 100) return 1;
	return 2;
}

/* --- session11 batch 14: 8-byte / unsigned return handling --- */

long long probe_ret_ll_add(long long a, long long b) { return a + b; }
unsigned probe_ret_usub(unsigned a, unsigned b) { return a - b; }
long long probe_ret_ll_shift2(long long x, int n) { return x << n; }
unsigned long long probe_ret_ull(unsigned long long x) { return x >> 1; }

unsigned char probe_ret_uchar(int x) { return (unsigned char)(x & 0xff); }
