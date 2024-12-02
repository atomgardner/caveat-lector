#include <stdio.h>

#include "mersenne-twister.h"

uint32_t a = 0x9d2c5680;
uint32_t b = 0xefc60000;

//
// TODO:
// 	. is there a common algo?
// 	. make this more intelligible
//
uint32_t untemper(uint32_t z)
{
	//
	// This is quite fiddly; the tempering goes like this:
	//
	// 	w = v ^ (v >> 11);
	// 	x = w ^ ((w << 7) & a)
	// 	y = x ^ ((x << 15) & b)
	// 	z = y ^ (y >> 18);
	// 	return z;
	//
	// We invert it by inverting each step.
	//

	uint32_t v, w, x, y;

	//
	// This is an easy one. Since |z| == 32,
	// 	z = [y0, ..., y31] ^ [0, ..., y0, ... y13]
	// 	  = [y0, ..., y0 ^ y18, ... y13 ^ y31]
	// To recover y, we must know y0..13, which is just z >> 18.
	//

	y = z ^ (z >> 18);

	//
	// This one requires two steps. We can not x15,16 must be solved before x0,1
	//
	//	y = x ^ ((x<<15) & b)
	//	  = [x0^(x15 & b0), ..., x15^(x30 & b15), x16^(x31 & b16), x17, ...]
	//	N.B., 
	//	y[17,32) = x[17,32)
	//

	uint32_t mask = (((y & 3) & (b >> 15)) << 15);
	x = y ^ mask; // solve for x15,16
	x ^= ((y << 15) & ~(uint32_t)3 & b); // solve for x0..14

	//
	// This is basically the same as above but with additional overlaps.
	//
	//	x = w ^ ((w<<7) & a)
	//	  = [w0 ^ (w7 & a0), ... w24 ^ (w31 & a24), w25, ... w31]
	//
	// 	mask = ((x & 0x7f) & (a >> 7)) << 7;
	//
	//	x = x ^ mask
	//	  = [w0 ^ (w7 & a0), ... , w17 ^ (w24 & a17), w18, ... ]
	//        = [w0 ^ (w7 & a0), ...  w11 ^ (w18 & a11), ...
	//          	, w17 ^ (w24 & a17), w18, ... w31]
	//

	mask = ((x & 0x7f) & (a >> 7)) << 7;
	w = x ^ mask;

	mask = ((w >> 7) & (a >> 14) & 0x7f) << 14;
	w ^= mask;

	mask = ((w >> 14) & (a >> 21) & 0x7f) << 21;
	w ^= mask;

	mask = ((w >> 21) & (a >> 28) & 0xf) << 28;
	w ^= mask;

	//
	// And the same again,
	//	w = v ^ (v>>11)
	//	  = [v0 , ... , v10, v11 ^ v0, ... v31 ^ v20]
	//
	// Recover v11..21, and then v22..31.
	//
	mask = (w & (0x7ff) << 21) >> 11;
	v = mask ^ w;

	mask = (v & (0x3ff) << 11) >> 11;
	v ^= mask;

	return v;
}

void mt_clone(mersenne_twister *mt, mersenne_twister *clone)
{
	uint32_t z;
	for (size_t k = 0; k < 624; k++) {
		z = mt_emit(mt);
		clone->x[k] = untemper(z);
	}
	clone->head = 624;
}

int main(void)
{
	mersenne_twister mt = { 0 };
	mersenne_twister clone = { 0 };
	mt_init(&mt, 5489);
	mt_clone(&mt, &clone);
	for (size_t k = 0; k < 48; k++)
		printf((k + 1) % 4 == 0 ? "%08x %08x\n" : "%08x %08x | ",
				mt_emit(&mt), mt_emit(&clone));
	return 0;
}
