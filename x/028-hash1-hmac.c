#include "sha1.h"
#include "hmac.h"

int main(void)
{
	struct blob secret_key;
	struct blob msg = { 0 }, digest = { 0 };
	struct hmac hmac = { 0 };

	blob_init_rand(&secret_key, 20);
	blob_add(&msg, (uint8_t *)"foo bar baz lur man", 20);

	hmac.key = &secret_key;
	hmac.hash = sha1_oneshot;

	// create the HMAC
	if (!hmac_create(&hmac, &msg, &digest)) {
		printf("did you specify a message???\n");
		return EXIT_FAILURE;
	}

	printf("should see `valid!`: ");
	if (hmac_validate(&hmac, &msg, &digest))
		puts("valid!");
	else
		puts("invalid!");

	// Change message but retain hash; hmac should be invalid
	msg.buf[0] = 'g';
	printf("should see `invalid!`: ");
	if (hmac_validate(&hmac, &msg, &digest))
		puts("valid!");
	else
		puts("invalid!");

	return EXIT_SUCCESS;
}
