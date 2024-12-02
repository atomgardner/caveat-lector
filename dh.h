#ifndef DH_H
#define DH_H

#include <gmp.h>
#include <time.h>

#include "blob.h"
#include "sha1.h"

// struct dffie_helman {
struct dh_pair {
	mpz_t priv, pub;
};

// dh_init_default initializes `p` and `g` to NIST-favoured values.
void dh_init_default(mpz_t p, mpz_t g)
{
	mpz_init_set_str(p,
		"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
		"e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
		"3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
		"6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
		"24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
		"c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
		"bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
		"fffffffffffff", 16);
	mpz_init_set_str(g, "2", 16);
}

void dh_pair_create(struct dh_pair *dh, mpz_t p, mpz_t g)
{
	struct timespec t = { 0 };
	gmp_randstate_t prng_state;

	clock_gettime(CLOCK_MONOTONIC, &t);
	gmp_randinit_default(prng_state);
	gmp_randseed_ui(prng_state, t.tv_nsec);

	mpz_init(dh->priv);
	mpz_init(dh->pub);

	mpz_urandomm(dh->priv, prng_state, p);
	mpz_powm(dh->pub, g, dh->priv, p);
}

// dh_derive_session_key uses the provided Diffie-Hellman pair to calculate a
// session key.
//
// . fix p, g
// . generate a = unif([0...p-1])
// . derive A = g^a % p
// . generate b % p
// . derive B = g^b % p
//
// A and B are public keys
//
// session key: hash(s) = hash(B^a % p) = hash(A^b % p)
void dh_derive_session_key(struct dh_pair *dh, struct blob *key, mpz_t pub, mpz_t p)
{
	mpz_t k;
	size_t cnt;
	uint8_t *buf;
	struct blob b = { 0 };

	mpz_init(k);
	mpz_powm(k, pub, dh->priv, p);

	buf = (uint8_t *)mpz_export(NULL, &cnt, 1, 8, 1, 0, k);
	blob_add(&b, buf, cnt);
	sha1_oneshot(&b, key);

	blob_free(&b);
	free(buf);
}

#endif
