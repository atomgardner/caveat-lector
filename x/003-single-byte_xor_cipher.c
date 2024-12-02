#include <stdio.h>

#include "blob.h"
#include "stats.h"
#include "break.h"

char thing[] =  "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

int main(int argc, char *argv[]) {
	struct blob a;
	uint8_t mask;

	if (argc == 2)
		blob_from_hex(&a, (uint8_t *)argv[1]);
	else
		blob_from_hex(&a, (uint8_t *)thing);

	mask = break_single_byte_xor(&a, NULL);
	blob_xor_mask(&a, mask);
	printf("%s\n", a.buf);

	return 0;
}
