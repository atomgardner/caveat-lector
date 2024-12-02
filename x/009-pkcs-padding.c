#include <stdio.h>

#include "blob.h"

int main(void)
{
	uint8_t msg[] = "YELLOW SUBMARINE";

	struct blob *s = blob_from_buf(msg, sizeof(msg) - 1);
	blob_pad_pkcs7(s, 20);

	printf("%s |> ", msg);
	blob_print_hex(s);
}
