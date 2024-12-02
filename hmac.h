#ifndef HMAC_H
#define HMAC_H

#include "blob.h"

struct hmac {
	struct blob *key;
	void (*hash)(struct blob *msg, struct blob *digest);
};

int hmac_create(struct hmac *hmac, struct blob *msg, struct blob *digest)
{
	struct blob tmp = { 0 };

	if (!hmac || !msg || !digest)
		return 0;

	blob_add_slice(&tmp, hmac->key);
	blob_add_slice(&tmp, msg);
	hmac->hash(&tmp, digest);
	//
	// probably should zero out the key if we're doing ``real" crypto?
	//
	blob_free(&tmp);
	return 1;
}

int hmac_validate(struct hmac *hmac, struct blob *msg, struct blob *digest)
{
	struct blob real = { 0 };

	if (!digest || !msg || !hmac)
		return 0;

	hmac_create(hmac, msg, &real);
	if (digest->len != real.len)
		return 0;

	int res = 1;
	for (size_t t = 0; t < real.len; t++)
		res &= digest->buf[t] == real.buf[t];

	blob_free(&real);
	return res;
}

#endif
