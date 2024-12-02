#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rand.h>

#include "blob.h"

unsigned char k[16];
unsigned char i[16];
struct blob *key;
struct blob *iv;

struct blob *first(struct blob *user)
{
	uint8_t prefix[] = "comment1=cooking%20MCs;userdata=";
	uint8_t suffix[] = ";comment2=%20like%20a%20pound%20of%20bacon";

	// TODO: escape "=" and ";"
	struct blob *res = blob_from_buf(prefix, sizeof(prefix) - 1);
	blob_add_slice(res, user);
	blob_add(res, suffix, sizeof(suffix) - 1);
	blob_pad_pkcs7(res, 16);

	blob_encrypt_aes_cbc(res, key, iv);
	return res;
}

void *second(struct blob *ct)
{
	uint8_t admin[] = ";admin=true;";

	blob_decrypt_aes_cbc(ct, key, iv);
	blob_print(ct, 0);
	return memmem(ct->buf, ct->len, admin, sizeof(admin) - 1);
}

int main(void)
{
	// The plaintext abstracts to:
	//
	// 	32 bytes | user controlled | 42 bytes | padding
	//
	// AES block size is 16 bytes. The prefix is two blocks, but
	// the suffix is six bytes short.
	//
	// If [user controlled] is 7 bytes, the final byte of suffix will be
	// pushed into a new block, and that block will be PKCS7-padded with 15
	// '0x0f's
	uint8_t input_buf[] = "aaaaaaa";
	struct blob *input = blob_from_buf(input_buf, sizeof(input_buf) - 1);

	// Recall that the CBC decryption for a single block is
	//
	// 	m_i = d(c_i) ^ c_{i-1}
	//
	// Therefore XORing the i-1th block with \x0f will zero the PT padding.
	// The zeroed padding can then be XORed with data of our chosing.
	//
	//     m_i = d(c_i) ^ (c{i-1} ^ (payload* ^ \0x0f))
	uint8_t payload[] = "\x00;admin=true;\x03\x03\x03";
	for (size_t i = 0; i < sizeof(payload) - 1; i++)
		payload[i] ^= 0x0f;

	// Let it rip
	RAND_bytes(i, sizeof(i));
	RAND_bytes(k, sizeof(k));
	iv = blob_from_buf(i, sizeof(i));
	key = blob_from_buf(k, sizeof(k));

	struct blob *ct = first(input);

        // start editing at 65, one byte past the beginning of block n-1
        // prefix = 32 bytes = 2 blocks
        // user input + suffix = 49 bytes = 4 blocks + 1 byte
        // padding = final byte of suffix + 15 * 0x0f
	//
        // The desired payload ";admin=true;" is 12 bytes long.
	//
        // ecb_decrypt(c_{n-1}) ^ c_{n-2}
	//
	// m_{n-2}, m_{n-1} = [ound%20of%20baco] [n\0xf\0xf\0xf...]
        off_t offset = 64;
	for (size_t i = 0; i < sizeof(payload) - 1; i++)
		ct->buf[offset + i] ^= payload[i];

	if (second(ct))
		puts("pwned");

	return 0;
}
