#include <stdio.h>

#include "blob.h"

int main(int argc, char *argv[])
{
	struct blob a;

	if (argc < 2)
		return -1;

	if (!blob_from_hex(&a, (uint8_t *)argv[1])) {
		printf("error: bad hex string\n");
		return 1;
	}

	uint8_t *s = blob_to_b64(&a);
	printf("%s\n", s);

	return 0;
}
