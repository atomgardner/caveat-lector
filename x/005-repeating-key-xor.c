#include <stdio.h>
#include <string.h>

#include "blob.h"

uint8_t stanza[] = "Burning 'em, if you ain't quick and nimble\n"
		"I go crazy when I hear a cymbal";

int main(const int argc, const char *argv[])
{
	struct blob *p = blob_from_buf(stanza, strlen((char *)stanza));
	struct blob *k = blob_from_buf((uint8_t *)"ICE", strlen("ICE"));

	blob_xor_mask_repeating(p, k);
	uint8_t *ct = blob_to_hex(p);

	printf("%s\n", ct);
}
