/* Classic swap via an explicit temp variable -- the "normal" counterpart
 * to xor_swap_pair's no-temp variant, same two out-parameters. */
void swap_via_temp(long *a, long *b) {
	long tmp = *a;
	*a = *b;
	*b = tmp;
}
