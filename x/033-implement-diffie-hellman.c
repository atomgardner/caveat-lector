#include <stdio.h>
#include <time.h>

#include "../dh.h"

int main(void)
{
	mpz_t p, g;
	struct dh_pair dh_A = { 0 }, dh_B = { 0 };
	struct blob session_A = { 0 }, session_B = { 0 };

	dh_init_default(p, g);
	dh_pair_create(&dh_A, p, g); // private and public keys

	// A sends p, g, A -> B
	dh_pair_create(&dh_B, p, g);

	// public keys are A = g^a %p, B = g^b %p
	dh_derive_session_key(&dh_A, &session_A, dh_B.pub, p);
	dh_derive_session_key(&dh_B, &session_B, dh_A.pub, p);

	printf("s_A: ");
	blob_print_hex(&session_A);
	printf("s_B: ");
       	blob_print_hex(&session_B);

	return 0;
}
