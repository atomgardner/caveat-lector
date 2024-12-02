#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

#include "blob.h"

#define AES_BLK_SZ 16

struct blob secret_key;

struct blob *first(struct blob *user)
{
	uint8_t prefix[] = "comment1=cooking%20MCs;userdata=";
	uint8_t suffix[] = ";comment2=%20like%20a%20pound%20of%20bacon";

	if (!secret_key.len)
		blob_init_rand(&secret_key, AES_BLK_SZ);

	struct blob *msg = blob_from_buf(prefix, sizeof(prefix) - 1);

	//
	// here we perform some input sanitization by appending `\` to
	// occurrences of `=` and `;`.
	//
	for (size_t i = 0; i < user->len; i++) {
		if (user->buf[i] == '=' || user->buf[i] == ';')
			blob_add_byte(msg, '\\', 1);
		blob_add_byte(msg, user->buf[i], 1);
	}
	blob_add(msg, suffix, sizeof(suffix) - 1);

	blob_do_aes_ctr(msg, &secret_key);
	return msg;
}

int second(struct blob *msg)
{
	uint8_t admin[] = "admin=true;";
	int res = 0;

	blob_do_aes_ctr(msg, &secret_key);
	uint8_t *p = memmem(msg->buf, msg->len, admin, sizeof(admin) - 1);
	if (p != NULL && p != msg->buf && *(p - 1) != '\\') // There's probably a corner case here
		res = 1;
	blob_do_aes_ctr(msg, &secret_key);

	return res;
}

int main(void)
{
	struct blob *msg, *input;
	uint8_t payload[] = "pwned;admin=true";

	input = blob_from_buf(payload, sizeof(payload) - 1);

	msg = first(input);
	if (second(msg))
		printf("pwned\n");
	else
		printf("not pwned\n");

	free(msg->buf);
	free(msg);

	//
	// This attack is similar to the previous CTR attack: 1. send in zeros to
	// get keystream; 2. XOR the keystream with the payload.
	//
	blob_release(input);
	blob_add_byte(input, 0x00, sizeof(payload) -1);

	msg = first(input);
	for (size_t t = 0; t < 16; t++)
		//
		// prefix is always length 32
		//
		msg->buf[32 + t] ^= payload[t];
			
	if (second(msg))
		printf("pwned\n");
	else
		printf("not pwned\n");
}
