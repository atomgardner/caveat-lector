#include <math.h>

#include "stats.h"

struct freq_table ft_default;

//
// This table does not sum to 1. I couldn't find any case-sensitive tables that
// also included punctuation.
//
float freq_english[256] = {
	[' '] = 0.1918182,
	// >>>>>>>> these are faked and made up
	['-'] = 0.0001,
	['/'] = 0.0001,
	[','] = 0.0001,
	['.'] = 0.0001,
	[':'] = 0.0001,
	[';'] = 0.0001,
	['*'] = 0.0001,
	[')'] = 0.0001,
	['('] = 0.0001,
	['$'] = 0.0001,
	['\''] = 0.0001,
	// <<<<<<<<

	['A'] = 0.0651738,
	['B'] = 0.0124248,
	['C'] = 0.0217339,
	['D'] = 0.0349835,
	['E'] = 0.1041442,
	['F'] = 0.0197881,
	['G'] = 0.0158610,
	['H'] = 0.0492888,
	['I'] = 0.0558094,
	['J'] = 0.0009033,
	['K'] = 0.0050529,
	['L'] = 0.0331490,
	['M'] = 0.0202124,
	['N'] = 0.0564513,
	['O'] = 0.0596302,
	['P'] = 0.0137645,
	['Q'] = 0.0008606,
	['R'] = 0.0497563,
	['S'] = 0.0515760,
	['T'] = 0.0729357,
	['U'] = 0.0225134,
	['V'] = 0.0082903,
	['W'] = 0.0171272,
	['X'] = 0.0013692,
	['Y'] = 0.0145984,
	['Z'] = 0.0007836,

	['a'] = 0.0651738,
	['b'] = 0.0124248,
	['c'] = 0.0217339,
	['d'] = 0.0349835,
	['e'] = 0.1041442,
	['f'] = 0.0197881,
	['g'] = 0.0158610,
	['h'] = 0.0492888,
	['i'] = 0.0558094,
	['j'] = 0.0009033,
	['k'] = 0.0050529,
	['l'] = 0.0331490,
	['m'] = 0.0202124,
	['n'] = 0.0564513,
	['o'] = 0.0596302,
	['p'] = 0.0137645,
	['q'] = 0.0008606,
	['r'] = 0.0497563,
	['s'] = 0.0515760,
	['t'] = 0.0729357,
	['u'] = 0.0225134,
	['v'] = 0.0082903,
	['w'] = 0.0171272,
	['x'] = 0.0013692,
	['y'] = 0.0145984,
	['z'] = 0.0007836,
};

void freq_table_init(struct freq_table *ft)
{
	for (int i = 0; i < (2 << 7); i++)
		ft->count[i] = 0;
}

void freq_table_populate(struct freq_table *ft, uint8_t *str, size_t len)
{
	for (size_t n = 0; n < len; n++)
		ft->count[(uint8_t)str[n]]++;
}

float score_english(uint8_t *str, size_t len)
{
	float res = 0;

	freq_table_init(&ft_default);
	freq_table_populate(&ft_default, str, len);

	//
	// I initially thought a chi-squared statistic would be ideal here, but
	// I couldn't get it to work proplery with non-ascii bytes (there's a
	// division by zero that needs to be handled.)
	//
	for (size_t k = 0; k < 256; k++)
		res += ft_default.count[k] * (freq_english[k] != 0 ? freq_english[k] : -1);

	return res;
}
