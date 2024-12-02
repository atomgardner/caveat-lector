#include <stdio.h>

#include <openssl/rand.h>

#include "blob.h"

struct profile {
	char *email;
	int uid;
	char *role;
};


unsigned char k[16];
struct blob *key;

void profile_for(uint8_t *email, struct blob *enc)
{
	static int initialized;

	if (!initialized) {
		initialized = 1;
		RAND_bytes(k, sizeof(k));
		key = blob_from_buf(k, sizeof(k));
	}

	uint8_t suffix[] = "&uid=10&role=user";
	uint8_t *p;

	blob_add(enc, (uint8_t *)"email=", sizeof("email=") - 1);

	for (p = email; *p && *p != '&' && *p != '='; p++)
		blob_add(enc, p, 1);

	blob_add(enc, suffix, sizeof(suffix) - 1);
	blob_encrypt_aes_ecb(enc, key);
}

void decrypt_and_print(struct blob *enc)
{
	blob_decrypt_aes_ecb(enc, key);
	blob_print(enc, 0);
}

//
// TODO: this is really cool; explain it properly
//
int main(void)
{
	struct blob one, two, *three;
	uint8_t user_one[] = "attack()@dawn";
	uint8_t user_two[] = "aaaaaaaaaa" "admin"
			"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";

	blob_init(&one, 0);
	blob_init(&two, 0);

	profile_for(user_one, &one);
	profile_for(user_two, &two);

	three = blob_from_buf(one.buf, 32);
	blob_add(three, two.buf + 16, 16);

	decrypt_and_print(three);
}
