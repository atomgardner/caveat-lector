#include "metrics.h"

size_t distance_hamming(uint8_t *a, uint8_t *b, size_t n)
{
	size_t ret = 0;

	for (size_t k = 0; k < n; k++) {
		uint8_t c = a[k] ^ b[k];

		while (c != 0) {
			ret += c & 0x01;
			c >>= 1;
		}
	}

	return ret;
}
