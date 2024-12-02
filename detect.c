#include "blob.h"
#include "utils.h"

size_t detect_aes_ecb(struct blob *s, size_t len)
{
	size_t i, j;
	size_t res = 0;

	for (i = 0; i < s->len - len; i += len)
		for (j = i + len; j < s->len; j += len)
			res += blocks_eq(s->buf + i, s->buf + j , len);

	return res;
}
