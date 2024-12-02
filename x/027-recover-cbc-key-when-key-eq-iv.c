#include <stdio.h>
#include "blob.h"

// 
// Ci = E(Pi^Ci-1) // IV is XORed before CBCing
//
struct blob secret_key;
void encrypter(struct blob *msg)
{
	if (!secret_key.len)
		blob_init_rand(&secret_key, 16);

	//
	// bad to use IV = key
	//
	blob_encrypt_aes_cbc(msg, &secret_key, &secret_key);
}

struct blob *decrypter_and_validator(struct blob *msg)
{
	blob_decrypt_aes_cbc(msg, &secret_key, &secret_key);

	for (size_t i = 0; i < msg->len; i++)
		//
		// XXX| apparently this is realistic; but I probably
		// XXX| misunderstood the question.
		//
		if (msg->buf[i] >= 0x7f)
			return msg;

	blob_encrypt_aes_cbc(msg, &secret_key, &secret_key);
	return NULL;
}

int main(void)
{
	// send in 3 blocks
	struct blob input, *constructed;
	blob_init_rand(&input, 16 * 3);
	encrypter(&input);

	// construct C1|0|C1
	constructed = blob_from_buf(input.buf, 16);
	blob_add_byte(constructed, 0x00, 16);
	blob_add(constructed, input.buf, 16);

	//
	// Decryption probably short-circuits due to high ASCII. When this
	// happens we will have
	//
	// 	P1^IV^IV | rubbish | P1^IV
	//
	// XORing those blocks gives us the IV. But IV == key, so now we have
	// the key.
	//
	decrypter_and_validator(constructed);
	for (size_t t = 0; t < 16; t++)
		constructed->buf[t] ^= constructed->buf[32 + t];

	constructed->len = 16; // hacky
	printf( "want: %s\n got: %s\n",
		blob_to_hex(&secret_key), blob_to_hex(constructed)); // leaky
	constructed->len = 48; // hacky & pointless
	
	return 0;
}

