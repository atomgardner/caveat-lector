#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/rand.h>

#include "blob.h"
#include "utils.h"


short visualize;

#define AES_BLK_SZ 16

unsigned char k[16];
unsigned char i[16];
struct blob *key;
struct blob *iv;

uint8_t *strings[] = {
	(uint8_t *)"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
	(uint8_t *)"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
	(uint8_t *)"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
	(uint8_t *)"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
	(uint8_t *)"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
	(uint8_t *)"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
	(uint8_t *)"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
	(uint8_t *)"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
	(uint8_t *)"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
	(uint8_t *)"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
};

struct blob *generate_token(struct blob *iv)
{
	uint8_t choice = rand() % 10;
	struct blob *res = blob_from_buf(strings[choice],
					strlen((char *)strings[choice]));

	blob_decode_b64(res);
	RAND_bytes(k, sizeof(k));
	key = blob_from_buf(k, sizeof(k));
	blob_encrypt_aes_cbc(res, key, iv);

	return res;
}

int decrypt_and_validate_padding(uint8_t *buf, size_t blk_cnt)
{
	struct blob *tmp = blob_from_buf(buf, blk_cnt*AES_BLK_SZ);

	blob_decrypt_aes_cbc(tmp, key, iv);
	int res = blob_validate_pkcs7(tmp);

	if (visualize) {
		uint8_t *distill = blob_to_hex(tmp);

		printf("%s\n", distill);
		free(distill);
	}
	
	// XXX: clunky af
	blob_free(tmp);
	free(tmp);

	return res;
}

//
// Suppose we're solving for block `n`.
//
void solve_block(struct blob *msg, size_t blk, uint8_t *solved) {
	for (size_t solving_for = 1; solving_for < 17; solving_for++) {
		if (visualize) {
			puts("before attack:");
			decrypt_and_validate_padding(msg->buf + (blk - 1)*AES_BLK_SZ, 2);
			printf("we want the last byte %ld from the end\n\n", solving_for);
		}

		//
		// fake the padding
		//
		for (size_t k = 1; k < solving_for; k++)
			msg->buf[blk*AES_BLK_SZ - k] ^= solved[16 - k] ^ solving_for;

		//
		// find the byte that gives good padding 
		//
		short found_one = 0;
		for (uint32_t a = 0x01; a < 0x100; a++) {
			msg->buf[blk*AES_BLK_SZ - solving_for] ^= a;

			if (decrypt_and_validate_padding(
					msg->buf + (blk - 1)*AES_BLK_SZ, 2)) {
				found_one = 1;
				msg->buf[blk*AES_BLK_SZ - solving_for] ^= a;
				solved[16 - solving_for] = a ^ solving_for;

				break;
			}

			msg->buf[blk*AES_BLK_SZ - solving_for] ^= a;
		}

		//
		// If the search above yields nothing, the byte we're looking
		// for equals the value of `solving_for`. This is a weird quirk
		// of my algorithm; there's probably a better way.
		//
		if (!found_one)
			solved[16 - solving_for] = solving_for;

		if (visualize) {
			printf("found: %02x\n", solved[16 - solving_for]);
		}

		//
		// unfake the padding
		//
		for (size_t k = 1; k < solving_for; k++)
			msg->buf[blk*AES_BLK_SZ - k] ^= solved[16 - k] ^ solving_for;
	}
}

int main(int argc, char *argv[])
{
	if (argc > 1)
		visualize = 1;

	srand(time(NULL));
	struct blob *msg, pt, msg_plus_iv;

	// TODO: tidy all this up into something easy and replayable:
	// 	struct aes_box = { };
	// 	aes_box_init(char *key, char *iv /* with random key/iv if null*/);
	RAND_bytes(i, sizeof(i));
	iv = blob_from_buf(i, sizeof(i));

	msg = generate_token(iv);

	//
	// attack starts here
	//
	blob_init(&pt, msg->len);
	blob_init(&msg_plus_iv, msg->len + iv->len);
	blob_add_slice(&msg_plus_iv, iv);
	blob_add_slice(&msg_plus_iv, msg);
	size_t blk_cnt = msg_plus_iv.len/AES_BLK_SZ;
	uint8_t solved[16];

	for (size_t blk = blk_cnt - 1; blk > 0; blk--) {
		solve_block(&msg_plus_iv, blk, solved);
		memcpy(&pt.buf[(blk - 1)*AES_BLK_SZ], solved, 16);
		pt.len += 16;
		if (visualize) {
			puts("solved: ");
			for (size_t k = (blk - 1)*AES_BLK_SZ; k < (blk_cnt - 1)*AES_BLK_SZ; k++)
				printf("%02x", pt.buf[k]);
			puts("");
		}
	}

	blob_print_and_strip_padding(&pt, 0);
	return 0;
}
