#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "mersenne-twister.h"

int main(void) {
	mersenne_twister known, unknown;

	sleep(rand() % 200);
	mt_init(&unknown, time(NULL));
	uint32_t x = mt_emit(&unknown);
	sleep(rand() % 100);

	for (time_t t = time(NULL); t > 0; t--) {
		mt_init(&known, t);
		if (x == mt_emit(&known)) {
			printf("seed: %lx\n", t);
			break;
		}
	}
	
}
