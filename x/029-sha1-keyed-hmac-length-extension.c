#include <stdio.h>

#include "blob.h"
#include "sha1.h"
#include "hmac.h"


//
// The model: attacker knows an HMAC and its corresponding message.
//
// This attack generates a valid HMAC for the message
// 	[real msg][padding][our msg]
// by initializing the sha1 algo's working variables to the HMAC for
// `[real msg]`.
//
// It seems like the lesson here is: When using an `H(k | m)` auth code,
// messages should be checked for blocks of unnecessary zeros that resemble
// valid padding.
//
int main(void)
{
	struct hmac hmac = { 0 };
	struct blob msg = { 0 }, digest = { 0 };
	uint8_t buf[] = "comment1=cooking%20MCs;userdata=foo;"
			"comment2=%20like%20a%20pound%20of%20bacon";
	uint8_t payload[] = ";admin=true;";
	struct blob secret_key = { 0 };
	uint8_t secret_len;

	blob_add(&msg, buf, sizeof(buf) - 1);

	RAND_bytes(&secret_len, 1);
	secret_len %= 24;
	secret_len += 8;
	blob_init_rand(&secret_key, secret_len);

	hmac.hash = sha1_oneshot;
	hmac.key = &secret_key;

	hmac_create(&hmac, &msg, &digest);

	//
	// We know padding is of the form 
	// 	0x01 | 0x00*n | (uint64_t)bit-length(secret_key | buf);
	//
	// The known message has length 77 bytes; however we do not know the
	// length of `secret_key`. We proceed by brute forcing the length. 
	//
	for (size_t guess_len = 77 + 8; guess_len < 77 + 8 + 32; guess_len++) {
		struct sha1 sha1 = { 0 };
		struct blob forged_suffix = { 0 };
		struct blob glue_padding = { 0 };
		struct blob forged_msg = { 0 };
		struct blob forged_digest = { 0 };

		//
		// Padding scheme has 3 steps:
		// 	- add a single `1` bit
		// 	- add zero bits until message length (mod 512b) is 64b
		// 	  short of zero
		// 	- fill the final 64b with the message length (in bits)
		//
		size_t overlap = guess_len % 64;
		size_t pad = 0;

		if (overlap < 56)
			pad = 56 - overlap;
		else
			pad = 56 + 64 - overlap;

		blob_add_byte(&glue_padding, 0x80, 1);
		blob_add_byte(&glue_padding, 0x00, pad - 1);
		for (size_t z = 0; z < 8; z++)
			blob_add_byte(&glue_padding,
				(8*guess_len >> (56 - 8*z)) & 0xff, 1);

		//
		// ! To generate the right hash, we need to glue here also.
		//
		blob_add(&forged_suffix, payload, sizeof(payload) - 1);
		blob_add_byte(&forged_suffix, 0x80, 1);
		size_t len_forged = guess_len + 
			glue_padding.len + (sizeof(payload) - 1);
		//
		// we know forged_suf lands on a message block boundary, so 
		// num of zeros =12 + 1 + x + 8 == 64 => 
		//
		blob_add_byte(&forged_suffix, 0x00, 64 - 12 - 1 - 8);
		for (size_t z = 0; z < 8; z++)
			blob_add_byte(&forged_suffix,
				(8*len_forged >> (56 - 8*z)) & 0xff, 1);

		sha1_init(&sha1, &forged_suffix);
		for (size_t t = 0; t < 5; t++)
			sha1.H[t] = ((uint32_t *)digest.buf)[t];

		sha1.N = 1; // we only want to hash the first message block
		sha1_hash(&sha1);
		blob_add(&forged_digest, (uint8_t *)sha1.H, 20); // be careful with endianness

		//
		// Add glue and fragment to the original message
		//
		blob_add_slice(&forged_msg, &msg);
		blob_add_slice(&forged_msg, &glue_padding);
		//
		// the call to sha1 above will pad the suffix out to message
		// block length; need to hack the length back to where it was
		// before being padded
		//
		blob_add(&forged_msg, forged_suffix.buf, sizeof(payload) - 1);

		//
		// construct hmac and validate
		//
		if (hmac_validate(&hmac, &forged_msg, &forged_digest)) {
			blob_print_ascii(&forged_msg);
			for (size_t t = 0; t < 5; t++)
				printf("%08x", ((uint32_t *)forged_digest.buf)[t]);
			puts("");
			break;
		}

		blob_free(&forged_msg);
		blob_free(&glue_padding);
		blob_free(&forged_suffix);
	}

	return 0;
}
