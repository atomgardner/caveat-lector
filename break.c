#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <time.h>

#include "break.h"
#include "metrics.h"
#include "blob.h"
#include "stats.h"

static size_t break_repeating_key_xor_find_key_length(struct blob *a)
{
	int sample_size = 100;
	float best = INFINITY;
	size_t res = 2;

	srand(time(NULL));

	for (size_t sz = 2; sz < 40; sz++) {
		float s = 0;

		for (size_t n = 0; n < sample_size; n++) {
			int x = rand() % (a->len / sz);
			int y = rand() % (a->len / sz);

			s += distance_hamming(a->buf + x*sz, a->buf + y*sz, sz);
		}

		s /= (float)sample_size * (float)sz;

		if (s < best) {
			best = s;
			res = sz;
		}
	}

	return res;
}

void break_repeating_key_xor(struct blob *a)
{
	size_t len;
	struct blob key;

	len = break_repeating_key_xor_find_key_length(a);
	blob_init(&key, len + 1);
	key.buf[len] = 0x00;
	key.len = len;

	for (size_t k = 0; k < len; k++) {
		struct blob *s = blob_take_every_nth(a, len, k);

		key.buf[k] = break_single_byte_xor(s, NULL);

		free(s);
	}

	printf("key: ");
	blob_print(&key, 0);
	blob_xor_mask_repeating(a, &key);
	blob_print(a, 0);
}

uint8_t break_single_byte_xor(struct blob *a, float *score_p)
{
	float best = 0;
	uint8_t mask = 0x00;

	for (uint32_t x = 0; x < 256; x++) {
		blob_xor_mask(a, (uint8_t)x);

		float score = score_english(a->buf, a->len);
		if (score > best) {
			best = score;
			mask = x;
		}

		blob_xor_mask(a, (char)x);
	}

	if (score_p)
		*score_p = best;

	return mask;
}
