#include <stdio.h>
#include <inttypes.h>

#include "mersenne-twister.h"

int main(void)
{
	mersenne_twister m;

	mt_init(&m, 5489);
	for (size_t k = 0; k < 100; k++) {
		printf((k + 1) % 10 == 0 ? "%08x\n" : "%08x ", mt_emit(&m));
	}

	return 0;
}
