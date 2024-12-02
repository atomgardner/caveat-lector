#include <stdio.h>
#include <stdlib.h>

#include <openssl/rand.h>
#include "blob.h"

int main(void) {
	struct blob *key, *iv, *test;
	uint8_t k[16], i[16];
	uint8_t test_msg[] = "foo foo foo foo " "foo foo foo foo " "A";

	RAND_bytes(i, sizeof(i));
	RAND_bytes(k, sizeof(k));
	iv = blob_from_buf(i, sizeof(i));
	key = blob_from_buf(k, sizeof(k));

	test = blob_from_buf(test_msg, sizeof(test_msg) - 1);

	blob_print(test, 0);
	blob_encrypt_aes_cbc(test, key, iv);
	blob_decrypt_aes_cbc(test, key, iv);
	blob_print(test, 0);

	return 0;
}
