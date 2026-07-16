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
