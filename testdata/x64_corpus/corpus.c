/* x86-64 breadth corpus for Gosleigh golden generation.
 *
 * Compiled with MSVC cl /c /Od (Windows x64 ABI: RCX,RDX,R8,R9 integer args).
 * Each function is self-contained (no external calls, no globals) so the .obj
 * .text bytes are position-independent and relocation-free -- the exact bytes
 * Ghidra analyzes are the bytes fed to the Gosleigh tree.
 *
 * Goldens (bytes + decompiled C) are produced by importing the .obj into
 * Ghidra 12 headless and dumping each function. See gen_goldens.py.
 */

/* 1. four register args summed (RCX+RDX+R8+R9). */
long add4(long a, long b, long c, long d) {
	return a + b + c + d;
}

/* 2. mixed arithmetic across four args. */
long poly4(long a, long b, long c, long d) {
	return a * b + c - d;
}

/* 3. three-way conditional (nested if/else). */
long max3(long a, long b, long c) {
	long m = a;
	if (b > m) m = b;
	if (c > m) m = c;
	return m;
}

/* 4. counted loop accumulator. */
long sum_to_n(long n) {
	long s = 0;
	for (long i = 1; i <= n; i++) {
		s += i;
	}
	return s;
}

/* 5. pointer-walk sum over an array. */
long sum_array(long *p, long n) {
	long s = 0;
	for (long i = 0; i < n; i++) {
		s += p[i];
	}
	return s;
}

/* 6. switch statement. */
long classify(long x) {
	switch (x) {
	case 0: return 100;
	case 1: return 200;
	case 2: return 300;
	case 3: return 400;
	default: return -1;
	}
}

/* 7. nested loop (longer: O(n*m) accumulate with inner conditional). */
long grid_score(long n, long m) {
	long total = 0;
	for (long i = 0; i < n; i++) {
		for (long j = 0; j < m; j++) {
			if (((i + j) & 1) == 0) {
				total += i * j;
			} else {
				total -= j;
			}
		}
	}
	return total;
}

/* 8. longer combined function: clamp, accumulate, branch, early return. */
long process(long *data, long n, long lo, long hi) {
	long acc = 0;
	long count = 0;
	for (long i = 0; i < n; i++) {
		long v = data[i];
		if (v < lo) {
			v = lo;
		} else if (v > hi) {
			v = hi;
		} else {
			count++;
		}
		acc += v;
	}
	if (count == 0) {
		return -1;
	}
	return acc / count;
}
