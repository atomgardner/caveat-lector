#include <stdio.h>

#define _GNU_SOURCE
#include <string.h>

#include <openssl/rand.h>

#include "mersenne-twister.h"
#include "blob.h"

int main(void)
{
	uint32_t key;
	struct blob msg = { 0 };
	uint8_t known[] = "AAAAAAAAAAAAAA";
	mersenne_twister mt;

	//
	// construct a known plaintext with random prefix
	//
	blob_init_rand(&msg, rand() % 140);
	blob_add(&msg, known, sizeof(known) - 1);

	//
	// random 16 bit key
	//
	RAND_bytes((uint8_t *)&key, 2);
	mt_init(&mt, key);
	mt_stream_cipher(&mt, &msg);

	//
	// since key is only 16 bits, we can just brute force?
	//
	for (uint32_t k = 0; k < (uint32_t)1 << 16; k++) {
		mt_init(&mt, k);
		mt_stream_cipher(&mt, &msg);

		if (!memcmp(msg.buf + msg.len - sizeof(known) + 1,
					known, sizeof(known) - 1)) {
			printf("  k: 0x%08x\nkey: 0x%08x\n", k, key);
			break;
		}

		mt_init(&mt, k);
		mt_stream_cipher(&mt, &msg);
	}

	return 0;
}
