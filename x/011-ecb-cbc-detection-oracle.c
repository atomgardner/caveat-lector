#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include <openssl/rand.h>

#include "detect.h"
#include "blob.h"

struct blob *encryption_oracle(uint8_t *msg, size_t len, int *mode)
{
	// generate
	//  - random key
	//  - 10-20 random bytes
	//  - cbc/ecb choice

	unsigned char k[16];
	struct blob *key;
	struct blob *out;
	unsigned char prefix[10];
	unsigned char suffix[10];

	RAND_bytes(k, sizeof(k));
	RAND_bytes(prefix, sizeof(prefix));
	RAND_bytes(suffix, sizeof(suffix));

	key = blob_from_buf(k, sizeof(k));
	out = blob_from_buf(prefix, 5 + rand() % 6);

	blob_add(out, msg, len);
	blob_add(out, suffix, 5 + rand() % 6);

	*mode = rand() % 2;

	if (*mode) {
		blob_encrypt_aes_ecb(out, key);
	} else {
		struct blob *iv;
		unsigned char i[16];

		RAND_bytes(k, sizeof(k));
		iv = blob_from_buf(i, sizeof(i));

		blob_encrypt_aes_cbc(out, key, iv);
	}

	return out;
}

int main(int argc, char *argv[])
{
	// know key size is 16 bytes
	// - send identical 3 blocks
	// - detect ecb
	uint8_t repeated_blocks[] = "AAAAAAAAAAAAAAA"
				"AAAAAAAAAAAAAAAA"
				"AAAAAAAAAAAAAAAA"
				"AAAAAAAAAAAAAAAA"
				"AAAAAAAAAAAAAAAA"
				"AAAAAAAAAAAAAAAA";

	srand(time(NULL));
	int mode;
	struct blob *s = encryption_oracle(repeated_blocks,
			sizeof(repeated_blocks) - 1, &mode);

	int res = detect_aes_ecb(s, 16);
	printf("got: %d want: %d\n", res > 0, mode);

	return 0;
}
