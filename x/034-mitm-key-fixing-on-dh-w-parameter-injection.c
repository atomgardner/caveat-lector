#include <gmp.h>

#include "dh.h"
#include "blob.h"

struct mitm {
	mpz_t A, B, p, g, m;
	struct blob s;
};

/**
 * A->M
 *     Send "p", "g", "A"
 * M->B
 *     Send "p", "g", "p"
 * B->M
 *     Send "B"
 * M->A
 *     Send "p"
 * A->M
 *     Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
 * M->B
 *     Relay that to B
 * B->M
 *     Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
 * M->A
 *     Relay that to A
 */
int main(void)
{
	mpz_t p, g;
	struct dh_pair alice = { 0 }, bob = { 0 };
	struct blob sk_A = { 0 }, sk_B = { 0 };
	struct mitm mallory = { 0 };

	// A->mallory| p,g,A
	// mallory->B| p,g,p # pretty good privacy
	// 	B.s = p^p mod p
	// 	    = 0 mod p
	// B->mallory| p,g,B
	// mallory->A| p,g,p
	// 	A.s = p^p mod p
	// 	    = 0 mod p
	//
	// Communication now proceeds using AES-CBC
	dh_init_default(p, g);
	dh_pair_create(&alice, p, g);
	dh_pair_create(&bob, p, g);

	// mallory.A = alice.pub;
	// mallory.p = p;
	// mallory.g = g;

	dh_derive_session_key(&alice, &sk_A, p, p);
	// mallory.B = bob.pub;
	dh_derive_session_key(&bob, &sk_B, p, p);
	mpz_init_set_str(mallory.m, "0", 10);

	size_t cnt;
	uint8_t *buf;
	struct blob b = { 0 };
	buf = mpz_export(NULL, &cnt, 1, 8, 1, 0, mallory.m);
	blob_add(&b, buf, cnt);
	sha1_oneshot(&b, &mallory.s);
	free(buf);
	blob_free(&b);

	printf("s_A: ");
	blob_print_hex(&sk_A);
	printf("s_B: ");
       	blob_print_hex(&sk_B);
	printf("s_mallory: ");
       	blob_print_hex(&mallory.s);
}
