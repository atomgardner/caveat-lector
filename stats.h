#ifndef UTILS_H
#define UTILS_H

#include <stdlib.h>
#include <inttypes.h>

struct freq_table {
	uint64_t count[2 << 7];
};

float score_english(uint8_t *str, size_t len);

#endif
