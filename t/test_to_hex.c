#include <stdio.h>

#include "blob.h"
#include "utils.h"

int main(void)
{
	uint8_t buf1[] = "foo bar this is a long one\x02\x03\x04";
	struct blob s = { 0 };
	blob_add(&s, buf1, sizeof(buf1) - 1);

	uint8_t *h = blob_to_hex(&s);
	printf("%s\n", h);

	free(h);
	blob_free(&s);
}
