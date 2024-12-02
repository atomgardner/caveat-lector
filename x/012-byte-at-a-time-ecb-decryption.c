#include <stdio.h>
#include <openssl/rand.h>

#include "blob.h"
#include "utils.h"

#define AES_BLK_SZ 16

void encryption_box(struct blob *msg, struct blob *out)
{
	static struct blob key, secret;

	if (msg == NULL && out == NULL) {
		blob_free(&key);
		blob_free(&secret);
	}

	if (!key.len) {
		uint8_t pt[] =  "Um9sbGluJyBpbiBt" "eSA1LjAKV2l0aCBt"
				"eSByYWctdG9wIGRv" "d24gc28gbXkgaGFp"
				"ciBjYW4gYmxvdwpU" "aGUgZ2lybGllcyBv"
				"biBzdGFuZGJ5IHdh" "dmluZyBqdXN0IHRv"
				"IHNheSBoaQpEaWQg" "eW91IHN0b3A/IE5v"
				"LCBJIGp1c3QgZHJv" "dmUgYnkK";

		blob_init_rand(&key, 16);
		blob_add(&secret, pt, sizeof(pt) - 1);
		blob_decode_b64(&secret);
	}

	blob_add_slice(out, msg);
	blob_add_slice(out, &secret);
	blob_encrypt_aes_ecb(out, &key);
}

ssize_t find_block_len(void)
{
	ssize_t res = -1;

	//
	// send 2 identical blocks until we detect a collision
	//
	for (res = 1; 2 * res < BUFSIZ; res++) {
		struct blob ct = { 0 };
		struct blob input = { 0 };

		blob_add_byte(&input, 'A', 2*res);
		encryption_box(&input, &ct);

		if (blocks_eq(ct.buf, ct.buf + res, res)) {
			blob_free(&input);
			blob_free(&ct);
			break;
		}

		blob_free(&input);
		blob_free(&ct);
	}

	return res;
}

// prefix must always have a length of AES_BLK_SZ - 1.
uint8_t search_for_collision(uint8_t *prefix, struct blob *target, size_t block)
{
	uint32_t x;
	struct blob pt = { 0 };
	
	blob_add(&pt, prefix, AES_BLK_SZ - 1);
	blob_add_byte(&pt, 0x00, 1);

	for (x = 1; x < 0xff; x++) {
		struct blob ct = { 0 };

		pt.buf[AES_BLK_SZ - 1] = (uint8_t)x;
		encryption_box(&pt, &ct);

		if (blocks_eq(
			target->buf + (block * AES_BLK_SZ),
			ct.buf, AES_BLK_SZ)
		) {
			blob_free(&ct);
			break;
		}

		blob_free(&ct);
	}

	blob_free(&pt);
	return (uint8_t)(x & 0xff); // really?
}

int main(void)
{
	struct blob msg = { 0 };
	ssize_t block_len;
	size_t block_count;

	block_len = find_block_len();
	printf("+| block len: %ld\n", block_len);

	//
	// Box(P) = ECB(P|M)
	// ------
	//
	// This is all about block boundaries and toying with their alignment.
	// Imagine the block len is L; we take p=constant, send the L messages:
	//
	//	0   [][m1m2m3...]
	// 	1   [p1][m1m2m3m...]
	// 	2   [p1p2][m1m2m3m...]
	// 	  ...
	// 	L-1 [p1p2..pL-1][m1m2m3m...],
	//
	// and save the returned ciphertexts into ct_cache. Since ECB is
	// bijective, these L ciphertexts define a dictionary of blocks that
	// can be used to recover M.
	// 	To solve for `m1`, we vary x over all bytes until the block,
	//
	// 		[p1...pL-1, x]
	//
	// matches ct_cache[L-1][0:16]. Now that we know `m1`,
	// to solve for `m2` we let x range over bytes until the block,
	//
	// 		[p1...pL-2, m1, x]
	//
	// matches ct_cache[L-2][0:16].
	//
	// Generalizing, to solve for m^b_n, the nth byte of block b, we
	// construct the block,
	//
	// 	m^b-1[L-n:L-1] | m^b[1:n-1] | x
	//
	// and let x range over bytes until a collision is found in
	// ctcache[pfxlen=n, block b]
	//
	struct blob prefix = { 0 };
	struct blob *ct_cache = calloc(block_len, sizeof(*ct_cache));

	for (size_t i = 0; i < block_len; i++) {
		blob_add_byte(&prefix, 'A', 1);
		encryption_box(&prefix, &ct_cache[i]);
	}
	blob_free(&prefix);
	block_count = ct_cache[0].len/block_len;

	blob_add_byte(&msg, 'A', 15);
	for (size_t n = 0; n < block_count; n++) {
		for (size_t i = 0; i < 16; i++) {
			uint8_t c = search_for_collision(
					msg.buf + n * block_len + i,
					&ct_cache[15 - i], n);
			blob_add_byte(&msg, c, 1);
			printf("%c", c);
		}
	}

	//
	// I'm trying to clean up but this is such a mess
	//
	encryption_box(NULL, NULL);
	for (size_t k = 0; k < block_len; k++)
		blob_free(&ct_cache[k]);
	free(ct_cache);

	return 0;
}
