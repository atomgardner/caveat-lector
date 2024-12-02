#include <stdio.h>

#include "blob.h"
#include "break.h"

int main(int argc, char *argv[])
{
	if (argc != 2)
		return 1;

	char *path = argv[1];

	struct blob all = { 0 };

	if (!blob_from_file(&all, path))
		return 1;

	struct blob **lines = NULL;
	size_t n = blob_split(&lines, &all, '\n');

	float best_score = 0;
	uint8_t best_mask = 0;
	size_t best_line = 0;

	for (size_t i = 0; i < n; i++) {
		float score;
		blob_decode_hex(lines[i]);
		uint8_t mask = break_single_byte_xor(lines[i], &score);

		if (score > best_score) {
			best_score = score;
			best_mask = mask;
			best_line = i;
		}
	}

	struct blob *winner = lines[best_line];
	blob_xor_mask(winner, best_mask);
	winner->buf[winner->len] = 0x00;
	printf("winner: %s", winner->buf);

	return 0;
}
