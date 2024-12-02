#include <stdio.h>
#include <string.h>

#include "sha1.h"

struct blob secret_key;

int main(int argc, char *argv[])
{

	if (argc > 1) {
		struct sha1 hash = { 0 };
		sha1_init(&hash, blob_from_buf((uint8_t *)argv[1], strlen(argv[1])));
		sha1_hash(&hash);
		printf("%08x%08x%08x%08x%08x: %s\n", hash.H[0],
			hash.H[1], hash.H[2], hash.H[3], hash.H[4],
			argv[1]);

		return 0;
	}

	struct blob empty = { 0 };
	struct blob abc = { 0 };
	blob_add(&abc, (uint8_t *)"abc", 4);

	struct sha1 sha_null = { 0 };
	sha1_init(&sha_null, &empty);
	sha1_hash(&sha_null);
	printf("%08x%08x%08x%08x%08x: %s\n", sha_null.H[0],
		sha_null.H[1], sha_null.H[2], sha_null.H[3], sha_null.H[4],
		empty.buf);

	struct sha1 sha_abc = { 0 };
	sha1_init(&sha_abc, &abc);
	sha1_hash(&sha_abc);
	printf("%08x%08x%08x%08x%08x: %s\n", sha_abc.H[0],
		sha_abc.H[1], sha_abc.H[2], sha_abc.H[3], sha_abc.H[4],
		abc.buf);

	struct blob oneshot = { 0 };
	struct blob oneshot_digest = { 0 };
	sha1_oneshot(&oneshot, &oneshot_digest);
	blob_print_hex(&oneshot_digest);

	blob_free(&abc);
	blob_free(&empty);
	return 0;
}
