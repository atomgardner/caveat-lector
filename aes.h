#ifndef AES_H
#define AES_H

#include "blob.h"

#define AES_BLK_SZ 16

struct aes_ctx {
	struct blob *key;
	struct blob *iv;

	size_t (*encrypt)(struct blob *in, struct blob *key);
	size_t (*decrypt)(struct blob *in, struct blob *key);
};

void init_aes_cbc(struct aes_ctx *ctx, size_t keylen)
{
}

void init_aes_ecb(struct aes_ctx *w, size_t keylen)
{
	blob_init_rand(w->key, keylen);
	w->encrypt = blob_encrypt_aes_ecb;
	w->decrypt = blob_decrypt_aes_ecb;
}

void init_aes_ctr(struct aes_ctx *ctx, size_t keylen)
{
	blob_init_rand(ctx->key, keylen);
	blob_init_rand(ctx->iv, keylen);
	ctx->encrypt = blob_do_aes_ctr;
	ctx->decrypt = blob_do_aes_ctr;
}

#endif
