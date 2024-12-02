#include <stdio.h>
#include <inttypes.h>

#include "hmac.h"
#include "sha1.h"
#include "blob.h"


int main(void)
{
	struct blob secret_key = { 0 };
	struct blob file_data = { 0 };
	struct blob digest = { 0 };
	struct hmac hmac = {
		.key = &secret_key,
		.hash = sha1_oneshot,
	};

	blob_init_rand(&secret_key, 16);
	blob_from_file(&file_data, (char *)"blob.c");
	hmac_create(&hmac, &file_data, &digest);
	blob_print_hex(&digest);

	blob_release(&digest);
	blob_release(&file_data);

	blob_from_file(&file_data, (char *)"blob.c");
	hmac_create(&hmac, &file_data, &digest);
	blob_print_hex(&digest);

	blob_free(&digest);
	blob_free(&file_data);
	blob_free(&secret_key);

	return 0;
}
