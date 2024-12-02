#ifndef SHA1_H
#define SHA1_H

#include <inttypes.h>
#include <stdio.h>
#include <openssl/rand.h>

#include "blob.h"

//
// SHA-1 is defined for messages with bitlength in [0, 2**64). This
// implementation can only handle message lengths that are multiples of eight.
//
// Refs:
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
// https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
//
struct sha1 {
	uint32_t schedule[80];	// words of the message schedule
	uint32_t a, b, c, d, e;	// working variables
	uint32_t H[5];		// hash value
	size_t N;		// number of 512-bit messages
	struct blob *msg;	// the message
};

struct blob_sha1_hmac {
	int32_t hash[5]; // [??] does this lead to weird struct padding
	struct blob *msg; 
};

//
// preprocessing
// . padding(M)
// 	len(M) = l
// 	M ||= 0b1
// 	k := the smallest non-negative soln to
// 		len(M) + k  =_512 448
// 		(l + 1) + k =_512 448
//	M ||= 0b0*k
//	M ||= (uint64_t)l (big endian)
//
//   This ensures that `len(M) % 512 == 0`.
//
// . initial hash
//
static int sha1_init(struct sha1 *s, struct blob *msg)
{
	uint64_t len = (uint64_t)msg->len;
	size_t overlap = len % 64;
	size_t pad = 0;

	if (overlap < 56)
		pad = 56 - overlap;
	else
		pad = 56 + 64 - overlap; // ~~~ be careful with signedness ~~~

	blob_add_byte(msg, 0x80, 1); // Bi 0b00000001 == Li 0x80
	blob_add_byte(msg, 0x00, pad - 1);
	for (int i = 0; i < 8; i++)
		blob_add_byte(msg, (len*8 >> (56 - 8*i)) & 0xff, 1);

	// assert(msg->len % 64 == 0);
	s->N = msg->len/64;
	s->msg = msg;

	//
	// NIST starts with these initial values. This implementation
	// intentionally keeps the working terms accessible.
	//
	s->H[0] = 0x67452301;
	s->H[1] = 0xefcdab89;
	s->H[2] = 0x98badcfe;
	s->H[3] = 0x10325476;
	s->H[4] = 0xc3d2e1f0;

	return 1;
}

static uint32_t K(size_t t) {
	if (0 <= t && t < 20)
		return (int32_t)0x5a827999;
	else if (20 <= t && t < 40)
		return (int32_t)0x6ed9eba1;
	else if (40 <= t && t < 60)
		return (int32_t)0x8f1bbcdc;
	else if (60 <= t && t < 80)
		return (int32_t)0xca62c1d6;
	else
		return 0;
}

#define ROTL(n, x) (int32_t)(((x) << (n)) | ((x) >> (32 - (n))))

static uint32_t f(size_t t, uint32_t x, uint32_t y, uint32_t z)
{
	if (0 <= t && t < 20) 
		return (x & y) ^ ((~x) & z);
	else if (20 <= t && t < 40)
		return x ^ y ^ z;
	else if (40 <= t && t < 60)
		return (x & y) ^ (x & z) ^ (y & z);
	else if (60 <= t && t < 80)
		return x ^ y ^ z;
	
	// shouldn't reach here
	return 0;
}

//
// hash computation
// . each message block is processed in order
// . just follow the spec
//
static uint32_t *sha1_hash(struct sha1 *s)
{
	uint32_t *word = (uint32_t *)s->msg->buf;

#define get_word(t) (int32_t)( \
	((word[(t)] & 0xff000000) >> 24) |\
	((word[(t)] & 0x00ff0000) >> 8)  |\
	((word[(t)] & 0x0000ff00) << 8)  |\
	((word[(t)] & 0x000000ff) << 24))

	for (size_t i = 0; i < s->N; i++) {
		//
		// Big-endianify the message. Intel chips do this:
		//
		// 	*(uint32_t *)"abc" == 0x00636261,
		//
		// but we want
		//
		// 	*(uint32_t *)"abc" == 0x61626300.
		//
		for (size_t t = 0; t < 16; t++)
			s->schedule[t]  = get_word(i * 16 + t);

		for (size_t t = 16; t < 80; t++)
			s->schedule[t] = ROTL(1, (
				s->schedule[t - 3] ^
				s->schedule[t - 8] ^
				s->schedule[t - 14] ^
				s->schedule[t - 16]));

		s->a = s->H[0];
		s->b = s->H[1];	
		s->c = s->H[2];	
		s->d = s->H[3];	
		s->e = s->H[4];	

		for (size_t t = 0; t < 80; t++) {
			uint32_t T = ROTL(5, s->a)
				+ f(t, s->b, s->c, s->d)
				+ s->e
				+ K(t)
				+ s->schedule[t];

			s->e = s->d;
			s->d = s->c;
			s->c = ROTL(30, s->b);
			s->b = s->a;
			s->a = T;
		}

		s->H[0] += s->a;
		s->H[1] += s->b;
		s->H[2] += s->c;
		s->H[3] += s->d;
		s->H[4] += s->e;
	}

	return s->H;
}

static void sha1_oneshot(struct blob *msg, struct blob *digest)
{
	struct sha1 hash = { 0 };

	sha1_init(&hash, msg);
	sha1_hash(&hash);
	blob_add(digest, (uint8_t *)hash.H, 20); // 32 * 5 bits === 20 bytes
}

#endif
