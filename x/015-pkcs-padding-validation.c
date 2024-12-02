#include <stdio.h>

#include "blob.h"


int main(void)
{
	uint8_t p0[] = "ICE ICE BABY ICE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10";
	uint8_t p1[] = "ICE ICE BABY\x04\x04\x04\x04";
	uint8_t p2[] = "ICE\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d";
	uint8_t p3[] = "ICE ICE BABY\x04\x04\x04\x01";

	uint8_t f0[] = "ICE ICE BABY\x05\x05\x05\x05";
	uint8_t f1[] = "\x20\x70\x75\x6d\x70\x69\x6e\x27\x08\x08\x08\x08\x08\x08\x08\x00";
	uint8_t f2[] = "ICE ICE BAB\0x4\x04\x04\x04\x04";
	uint8_t f4[] = "\x6f\x20\x67\x6f\x2\x07\x3\x6f\x6c\x6f\x07\x07\x07\x07\x07\x06\x07";

	struct blob *pass0 = blob_from_buf(p0, sizeof(p0) - 1);
	struct blob *pass1 = blob_from_buf(p1, sizeof(p1) - 1);
	struct blob *pass2 = blob_from_buf(p2, sizeof(p2) - 1);
	struct blob *pass3 = blob_from_buf(p3, sizeof(p3) - 1);

	struct blob *fail0 = blob_from_buf(f0, sizeof(f0) - 1);
	struct blob *fail1 = blob_from_buf(f1, sizeof(f1) - 1);
	struct blob *fail2 = blob_from_buf(f2, sizeof(f2) - 1);
	struct blob *fail4 = blob_from_buf(f4, sizeof(f4) - 1);

	if (blob_validate_pkcs7(pass0))
		puts("passed");
	else
		puts("failed");

	if (blob_validate_pkcs7(pass1))
		puts("passed");
	else
		puts("failed");

	if (blob_validate_pkcs7(pass2))
		puts("passed");
	else
		puts("failed");

	if (blob_validate_pkcs7(pass3))
		puts("passed");
	else
		puts("failed");


	if (!blob_validate_pkcs7(fail0))
		puts("passed");
	else
		puts("failed");
		
	if (!blob_validate_pkcs7(fail1))
		puts("passed");
	else
		puts("failed");

	if (!blob_validate_pkcs7(fail2))
		puts("passed");
	else
		puts("failed");

	if (!blob_validate_pkcs7(fail4))
		puts("passed");
	else
		puts("failed");

}
