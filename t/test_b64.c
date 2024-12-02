#include <stdio.h>

#include "blob.h"
#include "utils.h"


//
// The goal is to test this round trip:
//
//	hex . bytes . b64 . bytes . hex
//
int main(void)
{
	struct blob a = { 0 };
	uint8_t *b64;
	uint8_t msg[] = "49276d206b696c6c696e6720796f757220627261"
		"696e206c696b65206120706f69736f6e6f757320";
	uint8_t out[BUFSIZ] = { 0 };

	blob_from_hex(&a, msg);

	b64 = blob_to_b64(&a);
	printf("b64:\t%s\n", b64);

	size_t n = b64_to_bytes(b64, b64, strlen((char *)b64));

	bytes_to_hex(b64, n, out);

	printf("msg:\t%s\n"
		"rt:\t%s\n", msg, out);

	blob_free(&a);
}
