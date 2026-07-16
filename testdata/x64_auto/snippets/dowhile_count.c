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
