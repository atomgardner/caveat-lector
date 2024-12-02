#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <openssl/rand.h>

#include "blob.h"
#include "utils.h"

size_t find_block_len(void);

uint8_t as[1024];
unsigned char k[16];
unsigned char pfx[16];
size_t pfx_len;

uint8_t sec[] = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
	"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
	"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
	"YnkK";

struct blob *key, *secret;

struct blob *encryption_box(struct blob *msg)
{
	static int initialized;

	if (!initialized) {
		initialized = 1;

		RAND_bytes(k, sizeof(k));
		key = blob_from_buf(k, sizeof(k));

		RAND_bytes(pfx, sizeof(pfx));
		pfx_len = rand() % (sizeof(pfx) - 1);
		secret = blob_from_buf(sec, sizeof(sec) - 1);

		blob_decode_b64(secret);
	}

	struct blob *out;

	out = blob_from_buf(pfx, pfx_len);
	blob_add_slice(out, msg);
	blob_add_slice(out, secret);
	blob_encrypt_aes_ecb(out, key);

	return out;
}

void find_lengths(size_t *blk_sz, size_t *pad_sz)
{
	int done;
	size_t res, n;
	struct blob *pad, *ct;
	
	pad = blob_from_buf(as, 0);
	ct = encryption_box(pad);

	n = ct->len;

	free(pad);
	free(ct);

	for (done = 0, res = 1; res < sizeof(as) && !done; res++) {
		pad = blob_from_buf(as, res);
		ct = encryption_box(pad);

		if (ct->len != n) {
			*blk_sz = ct->len - n;
			done = 1;
		}

		free(pad);
		free(ct);
	}

	for (done = 0, res = 0; res < *blk_sz && !done; res++) {
		struct blob *pad0 = blob_from_buf(as, res);
		struct blob *pad1 = blob_from_buf(as, res + 1);
		struct blob *ct0 = encryption_box(pad0);
		struct blob *ct1 = encryption_box(pad1);

		if (blocks_eq(ct0->buf, ct1->buf, *blk_sz)) {
			*pad_sz = res;
			done = 1;
		}

		free(pad0);
		free(pad1);
		free(ct0);
		free(ct1);
	}
}

size_t find_block_len(void)
{
	size_t res;

	// send 2 identical blocks to genereate the expected collision.
	for (res = 1; 2 * res < sizeof(as); res++) {
		struct blob *input = blob_from_buf(as, 2*res);
		struct blob *ct = encryption_box(input);

		free(input);

		if (blocks_eq(ct->buf, ct->buf + res, res)) {
			free(ct);
			break;
		}

		free(ct);
	}

	return res;
}

struct blob *find_target(size_t delta, size_t block)
{
	struct blob *pre, *res; 

	pre = blob_from_buf(as, 16 - delta);
	res = encryption_box(pre);

	free(pre);
	return res;
}

// prefix must always have a length of block_len - 1.
uint8_t search_for_collision(uint8_t *prefix, struct blob *target, size_t block,
		size_t blk_sz, size_t pad_sz)
{
	char x;
	struct blob pt;
	
	blob_init(&pt, pad_sz + blk_sz);
	memcpy(pt.buf, as, pad_sz);
	memcpy(pt.buf + pad_sz, prefix, blk_sz - 1);
	pt.len = pad_sz + blk_sz;

	for (x = 1; x < 127; x++) {
		struct blob *ct;

		pt.buf[pt.len - 1] = x;
		ct = encryption_box(&pt);

		if (blocks_eq(target->buf + (block + 1) * blk_sz,
				ct->buf + blk_sz, blk_sz)) {
			free(ct);
			break;
		}

		free(ct);
	}

	return x;
}

int main(void)
{
	size_t pad_sz, blk_sz, block_count;
	struct blob pt;

	srand(time(NULL));

	memset(as, 'A', sizeof(as));

	pad_sz = blk_sz = 0;
	find_lengths(&blk_sz, &pad_sz);

	if (!(pad_sz || blk_sz))
		return 1;

	struct blob *target_dict[blk_sz];
	for (size_t i = 0; i < blk_sz; i++) {
		struct blob *pre, *res;

		pre = blob_from_buf(as, pad_sz + i);
		res = encryption_box(pre);

		free(pre);
		target_dict[i] = res;
	}

	block_count = target_dict[0]->len/blk_sz;

	blob_init(&pt, blk_sz - 1);
	pt.len = blk_sz - 1;
	memset(pt.buf, 'A', pt.len);

	/* [prefixAAAAAAAAAAA][P1     ... P16]
	 * [prefixAAAAAAAAAAA][A P1   ... P15]
	 * [prefixAAAAAAAAAAA][A A P1 ... P14]
	 * ...
	 * [prefixAAAAAAAAAAA][A A A  ... P1]
	 */
	for (int b = 0; b < block_count; b++)
		for (int i = 0; i < blk_sz; i++) {
			uint8_t c = search_for_collision(
				pt.buf + b * blk_sz + i,
				target_dict[blk_sz - 1 - i], b,
				blk_sz, pad_sz);
			blob_add(&pt, &c, 1);
		}
	
	blob_print(&pt, blk_sz - 1);
	return 0;
}
