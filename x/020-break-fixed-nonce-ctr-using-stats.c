#include <stdio.h>

#include "break.h"
#include "blob.h"
#include "stats.h"

int main(void)
{
	struct blob **lines;
	size_t cnt_lines, len_keystream;
	struct blob all = { 0 }, collection = { 0 };
	uint8_t *key;
	char *path = "f/20.txt";

	if (!blob_from_file(&all, path))
		return EXIT_FAILURE;

	cnt_lines = blob_split(&lines, &all, '\n');
	len_keystream = 0;

	for (size_t k = 0; k < cnt_lines; k++) {
		size_t len = blob_decode_b64(lines[k]);

		if (len > len_keystream)
			len_keystream = len;
	}

	key = malloc(len_keystream * sizeof(*key));
	blob_init(&collection, len_keystream);

	//
	// collect all of the position `k` bytes into `collection`, then break
	// a single byte xor cipher.
	//
	for (size_t k = 0; k < len_keystream; k++) {
		for (size_t j = 0; j < cnt_lines; j++)
			if (lines[j]->len >= k)
				blob_add(&collection, &lines[j]->buf[k], 1);

		key[k] = break_single_byte_xor(&collection, NULL);
		collection.len = 0;
	}

	for (size_t k = 0; k < cnt_lines; k++) {
		uint8_t *q = lines[k]->buf;

		for (uint8_t *p = q; p - q < lines[k]->len; p++)
			*p ^= key[p - q];

		blob_print(lines[k], 0);
	}

	return 0;
}
