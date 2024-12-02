#include <stdio.h>
#include <string.h>

#include "blob.h"
#include "utils.h"



int main(void)
{
	uint8_t the_key[] = "YELLOW SUBMARINE";
	uint8_t the_string[] = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/"
		"2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";

	struct blob *key = blob_from_buf(the_key, sizeof(the_key) - 1);
	struct blob *msg = blob_from_buf(the_string, sizeof(the_string) - 1);

	blob_decode_b64(msg);

	blob_do_aes_ctr(msg, key);

	blob_print(msg, 0);
}
