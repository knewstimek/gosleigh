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
