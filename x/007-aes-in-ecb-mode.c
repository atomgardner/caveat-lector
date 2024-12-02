#include <stdio.h>
#include <openssl/evp.h>

#include "blob.h"

int main(void)
{
	struct blob ct, *key;
	unsigned char k[] = "YELLOW SUBMARINE";

	blob_from_file(&ct, "./f/7.txt");
	blob_split_and_join(&ct, '\n');
	blob_decode_b64(&ct);

	key = blob_from_buf(k, sizeof(k));
	size_t len = blob_decrypt_aes_ecb(&ct, key);

	ct.buf[len] = '\0';

	printf("%s\n", ct.buf);
	return 0;
}
