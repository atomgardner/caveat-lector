#include <stdio.h>

#include "blob.h"

int main(void)
{
	uint8_t buf[16];

	struct blob *s = blob_from_buf(buf, sizeof(buf));
	blob_pad_pkcs7(s, 20);

	uint8_t *hex = blob_to_hex(s);

	printf("%s\n", hex);
	return 0;
}
