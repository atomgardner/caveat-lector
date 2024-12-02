#include <stdio.h>
#include <string.h>

#include "blob.h"
#include "utils.h"

int main(int argc, char *argv[]) {
	struct blob a, b;
	size_t len;

	if (argc != 3)
		return 1;

	len = strlen(argv[1]);

	if (len != strlen(argv[2]))
		return 1;

	blob_from_hex(&a, (uint8_t *)argv[1]);
	blob_from_hex(&b, (uint8_t *)argv[2]);

	xor_buffers(a.buf, b.buf, a.len);

	uint8_t *s = blob_to_hex(&a);

	printf("%s\n", s);
}
