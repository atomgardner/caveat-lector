#include "utils.h"

int blocks_eq(uint8_t *a, uint8_t *b, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		if (a[i] != b[i])
			return 0;

	return 1;
}

void xor_buffers(uint8_t *a, uint8_t *b, size_t len)
{
	size_t n;

	for (n = 0; n < len; n++)
		a[n] ^= b[n];
}

void bytes_to_hex(uint8_t *in, size_t len, uint8_t *out)
{
	char alpha_hex[] = "0123456789abcdef";

	size_t n = 0;
	uint8_t *p = in;

	while (p - in < len) {
		uint8_t c = (uint8_t)*p;

		out[n]     = alpha_hex[c / 16];
		out[n + 1] = alpha_hex[c % 16];

		p++;
		n += 2;
	}
}

int hex_to_bytes(uint8_t *str, uint8_t *buf)
{
	if (str == NULL)
		return 0;
	if (strlen((char *)str) % 2 == 1)
		return 0;

	uint8_t *p = buf;
	while (*str) {
		uint8_t next = 0x00;

		if (0 <= str[0] - '0' && str[0] - '0' < 10)
			next += str[0] - '0';
		else if ((0 <= str[0] - 'a' && str[0] - 'a' < 16)
		|| (0 <= str[0] - 'A' && str[0] - 'A' < 16))
			next += 10 + str[0] - 'a';
		else
			return 0;

		next *= 16;
		str++;

		if (0 <= str[0] - '0' && str[0] - '0' < 10)
			next += str[0] - '0';
		else if ((0 <= str[0] - 'a' && str[0] - 'a' < 16)
		|| (0 <= str[0] - 'A' && str[0] - 'A' < 16))
			next += 10 + str[0] - 'a';
		else
			return 0;

		*p = (char)next;

		p++;
		str++;
	}

	return 1;
}

static int b64_lookup(char c)
{
	if (0 <= c - 'A' && c - 'A' <= 25)
		return c - 'A';
	else if (0 <= c - 'a' && c - 'a' <= 25)
		return c - 'a' + 26;
	else if (0 <= c - '0' && c - '0' <= 9)
		return c - '0' + 52;
	else if (c == '+')
		return 62;
	else if (c == '/')
		return 63;
	else
		return 0;
}

/* out must be large enough to accommodate */
size_t bytes_to_b64(uint8_t *out, uint8_t *in, size_t len)
{
	char alpha_b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			    "abcdefghijklmnopqrstuvwxyz"
	"0123456789+/";

	size_t n = len;

	while (n >= 3) {
		*out++ = alpha_b64[in[0] >> 2];
		*out++ = alpha_b64[(in[0] & 0x03) << 4 | (in[1] & 0xf0) >> 4];
		*out++ = alpha_b64[(in[1] & 0x0f) << 2 | (in[2] & 0xc0) >> 6];
		*out++ = alpha_b64[in[2] & 0x3f];

		n -= 3;
		in += 3;
	}

	if (n == 1) {
		*out++ = alpha_b64[in[0] >> 2];
		*out++ = alpha_b64[(in[0] & 0x03) << 4];
		*out++ = '=';
		*out++ = '=';
	}

	if (n == 2) {
		*out++ = alpha_b64[in[0] >> 2];
		*out++ = alpha_b64[(in[0] & 0x03) << 4 | (in[1] & 0xf0) >> 4];
		*out++ = alpha_b64[(in[1] & 0x0f) << 4];
		*out++ = '=';
	}

	*out = 0x00;
	return len;
}

/* XXX: return a slice; don't lose length of buffer */
size_t b64_to_bytes(uint8_t *out, uint8_t *in, size_t inlen)
{
	size_t res = 0;
	uint8_t *p = in;
	uint8_t *q = out;

	if (inlen % 4)
		return 0;

	while (p - in < inlen) {
		uint32_t b = 0;

		b |= (b64_lookup(p[0]) << 18);
		b |= (b64_lookup(p[1]) << 12);
		b |= (b64_lookup(p[2]) << 6);
		b |= b64_lookup(p[3]);

		*q++ = (uint8_t)((b & (0xff << 16)) >> 16);
		*q++ = (uint8_t)((b & (0xff << 8)) >> 8);
		*q++ = (uint8_t)(b & 0xff);

		p += 4;
		res += 3;
	}

	p -= 4;
	if (p[3] == '=')
		res -= 1;
	if (p[2] == '=')
		res -= 1;

	return res;
}
