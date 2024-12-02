#include <stdio.h>
#include <openssl/evp.h>

#include "utils.h"
#include "blob.h"

int main(void)
{
	struct blob ct;
	unsigned char key[] = "YELLOW SUBMARINE";
	unsigned char iv[] = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
	EVP_CIPHER_CTX *ctx;
	int outl = 0;

	blob_from_file(&ct, "./f/10.txt");
	blob_split_and_join(&ct, '\n');
	blob_decode_b64(&ct);

	ctx = EVP_CIPHER_CTX_new();

	EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	
	size_t kl = sizeof(key) - 1;
	size_t n = ct.len - kl;
	while(n > 0) {
		EVP_DecryptUpdate(ctx, (unsigned char*)(ct.buf + n), &outl, (unsigned char*)(ct.buf + n), kl);
		xor_buffers(ct.buf + n, ct.buf + (n - kl), kl);

		n -= outl;
	}

	EVP_DecryptUpdate(ctx, (unsigned char*)ct.buf, &outl, (unsigned char*)ct.buf, kl);
	xor_buffers(ct.buf, iv, kl);

	ct.buf[ct.len] = 0x00;

	printf("%s", ct.buf);
	EVP_CIPHER_CTX_free(ctx);
	return 0;
}
