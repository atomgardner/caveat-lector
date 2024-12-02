#ifndef BREAK_H
#define BREAK_H

#include <inttypes.h>
#include <math.h>

#include "blob.h"

struct tuple {
	float score;
	uint8_t mask;
};

uint8_t break_single_byte_xor(struct blob *a, float *score_p);
void break_repeating_key_xor(struct blob *a);

#endif
