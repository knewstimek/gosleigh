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
