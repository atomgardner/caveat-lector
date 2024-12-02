#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "blob.h"
#include "utils.h"

#define AES_BLK_SZ 16

void blob_init(struct blob *s, size_t hint)
{
#ifdef blob_v2
	s->f = open_memstream((char **)&s->buf, &s->len);
	if (hint) {
		fseeko(s->f, hint, SEEK_SET);
		fseeko(s->f, 0, SEEK_SET);
		fflush(s->f);
	}
#else
	s->buf = NULL;
	s->cap = 0;
	s->len = 0;
	if (hint)
		blob_grow(s, hint);
#endif
}

void blob_init_rand(struct blob *s, size_t len)
{
	blob_init(s, len);
	RAND_bytes(s->buf, len);

#ifndef blob_v2
	s->len = len;
#endif
}

struct blob *blob_take_every_nth(struct blob *a, size_t nth,
		size_t offset)
{
	struct blob *res = calloc(1, sizeof(*res));

	blob_init(res, a->len / nth);

	for (size_t k = 0; offset + k*nth < a->len; k++)
		res->buf[k] = a->buf[offset + k*nth];

	res->len = a->len / nth;

	return res;
}

struct blob *blob_from_buf(uint8_t *buf, size_t len)
{
	struct blob *res = calloc(1, sizeof(*res));

	blob_init(res, len);
	memcpy(res->buf, buf, len);
	res->len = len;

	return res;
}

void blob_xor_buf(struct blob *a, uint8_t *b, size_t len)
{
	for (size_t k = 0; k < len; k++)
		a->buf[k] ^= b[k];
}

void blob_xor_mask_repeating(struct blob *plain, struct blob *key)
{
	for (size_t n = 0; n < plain->len; n++)
		plain->buf[n] = plain->buf[n] ^ key->buf[n % key->len];
}

void blob_xor_mask(struct blob *s, uint8_t c)
{
	for (size_t n = 0; n < s->len; n++)
		s->buf[n] = (char)((uint8_t)s->buf[n] ^ c);
}

int blob_decode_hex(struct blob *a)
{
	hex_to_bytes(a->buf, a->buf);
	a->len /= 2;

	return 1;
}

int blob_split_and_join(struct blob *sli, char delim)
{
	struct blob **lines = NULL;
	struct blob tmp = { 0 };

	size_t n = blob_split(&lines, sli, '\n');
	blob_release(sli);

	for (size_t k = 0; k < n; k++)
		blob_add_slice(&tmp, lines[k]);

	sli->len = tmp.len;
	sli->cap = tmp.cap;
	sli->buf = tmp.buf;

	free(lines);
	return 0;
}

int blob_split(struct blob ***split, struct blob *blob, char delim)
{
	size_t count = 0;
	uint8_t *left = blob->buf;

	for (uint8_t *right = left; right - blob->buf < blob->len; right++) {
		if (*right == delim || right - blob->buf == blob->len - 1) {
			count++;
			*split = realloc(*split, count * sizeof(*split));
			(*split)[count - 1] =  blob_from_buf(left, right - left);
			left = right + 1;
		}
	}

	return count;
}

int blob_from_file(struct blob *a, char *path)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		perror("open failed");

		return -1;
	}

	blob_init(a, 8192);

	for (;;) {
		ssize_t want = a->cap - a->len - 1;
		ssize_t got = read(fd, a->buf + a->len, want);

		a->len += got;
		if (!got)
			break;

		if (a->cap < 3*a->len/2)
			blob_grow(a, 8192);
	}

	close(fd);

	return a->len;
}

int blob_from_hex(struct blob *a, uint8_t *str)
{
	size_t len = strlen((char *)str);

	if (len % 2 != 0)
		return 0;

	blob_init(a, len/2);
	if (!hex_to_bytes(str, a->buf))
		return 0;

	a->len = strlen((char *)str) / 2;
	return 1;
}

void blob_grow(struct blob *s, size_t delta)
{
	if (!s->cap) {
		/* new blob */
		s->buf = NULL;
	}

	if (s->cap >= s->len + delta)
		return;

	s->buf = realloc(s->buf, s->cap + delta);
	if (s->buf == NULL)
		exit(1);

	s->cap += delta;
}

void blob_add_byte(struct blob *s, uint8_t byte, size_t count)
{
#ifndef blob_v2
	if (s->cap - s->len < count)
		blob_grow(s, count); // hopefully realloc does something sane here
#endif

	for (size_t k = 0; k < count; k++) {
#ifndef blob_v2
		s->buf[s->len++] = byte;
#else
		if(fputc(byte, s->f) != 1) {
			exit(1);
		}
		fflush(s->f);
#endif
	}
}

void blob_add(struct blob *s, const uint8_t *str, size_t len)
{
	if (s->cap - s->len < len)
		blob_grow(s, len);

	memcpy(s->buf + s->len, str, len);
	s->len += len;

#ifdef blob_v2
	fwrite(str, 1, len, s->f);
	fflush(s->f);
#endif
}

uint8_t *blob_to_hex(struct blob *a)
{
	uint8_t *ret;
	size_t len = 2 * a->len;
	ret = malloc((len + 1) * sizeof(*ret));

	bytes_to_hex(a->buf, a->len, ret);

	ret[len] = 0x00;
	return ret;
}

uint8_t *blob_to_b64(struct blob *a)
{
	size_t len = (4 * a->len)/3 + 4 * ((a->len % 3) != 0);

	uint8_t *s = malloc(len + 1);

	bytes_to_b64(s, a->buf, a->len);
	s[len] = 0x00;

	return s;
}

void blob_pad_pkcs7(struct blob *s, size_t blk_len)
{
	size_t k, diff = blk_len - s->len % blk_len;

	if (diff == blk_len)
		return;

	if (blob_validate_pkcs7(s))
		return;

	blob_grow(s, diff);
	if (!s->buf)
		exit(1);

	for (k = 0; k < diff; k++)
		s->buf[s->len + k] = (char)diff;

	s->len += diff;

	assert(s->len % blk_len == 0);
}

int blob_decode_b64(struct blob *a)
{
	a->len = b64_to_bytes(a->buf, a->buf, a->len);

	return a->len;
}

void blob_add_slice(struct blob *a, struct blob *b)
{
	blob_add(a, b->buf, b->len);
}

void blob_free(struct blob *buf)
{
	free(buf->buf);
}

void blob_release(struct blob *s)
{
	free(s->buf);
	blob_init(s, 0);
}

inline void blob_reset(struct blob *buf)
{
	buf->len = 0;
}

ssize_t blob_contains(struct blob *s, uint8_t b)
{
	for (size_t t = 0; t < s->len; t++)
		if (s->buf[t] == b)
			return t;

	return -1;
}

size_t blob_encrypt_aes_cbc(struct blob *s, struct blob *key, struct blob *iv)
{
	int outl;
	size_t n, blk_cnt;
	EVP_CIPHER_CTX *ctx;

	blob_pad_pkcs7(s, AES_BLK_SZ);

	ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key->buf, NULL);
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	xor_buffers(s->buf, iv->buf, AES_BLK_SZ);
	EVP_EncryptUpdate(ctx, s->buf, &outl, s->buf, AES_BLK_SZ);

	blk_cnt = s->len / AES_BLK_SZ;
	for (n = 1; n < blk_cnt; n++) {
		// xor current and prev block
		xor_buffers(s->buf +       n*AES_BLK_SZ,
			    s->buf + (n - 1)*AES_BLK_SZ, AES_BLK_SZ);

		EVP_EncryptUpdate(ctx,
			s->buf + n*AES_BLK_SZ, &outl,
			s->buf + n*AES_BLK_SZ, AES_BLK_SZ);

		assert(outl == AES_BLK_SZ);
	}

	return 0;
}

size_t blob_decrypt_aes_cbc(struct blob *s, struct blob *key, struct blob *iv)
{
	int outl;
	size_t n;
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

	EVP_DecryptInit_ex(ctx,
		EVP_aes_128_ecb(), NULL,
		key->buf, NULL);
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	
	n = s->len - AES_BLK_SZ;
	while (n > 0) {
		EVP_DecryptUpdate(ctx,
			s->buf + n, &outl,
			s->buf + n, key->len);
		xor_buffers(s->buf + n, s->buf + (n - key->len), key->len);

		n -= outl;
	}

	EVP_DecryptUpdate(ctx,
		s->buf, &outl,
		s->buf, key->len);
	xor_buffers(s->buf, iv->buf, key->len);

	return 0;
}

size_t blob_encrypt_aes_ecb(struct blob *s, struct blob *key)
{
	int outl;
	EVP_CIPHER_CTX *ctx;

	ctx = EVP_CIPHER_CTX_new();

	blob_pad_pkcs7(s, key->len);
	EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(),
			NULL, key->buf, NULL);
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	EVP_EncryptUpdate(ctx, s->buf, &outl,
			s->buf, s->len);
	EVP_EncryptFinal(ctx, s->buf, &outl);

	return 0;
}

size_t blob_decrypt_aes_ecb(struct blob *s, struct blob *key)
{
	size_t res = 0;
	int outl;
	EVP_CIPHER_CTX *ctx;

	ctx = EVP_CIPHER_CTX_new();

	EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(),
			NULL, key->buf, NULL);
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	
	EVP_DecryptUpdate(ctx, s->buf, &outl,
			s->buf, s->len);
	res += outl;
	EVP_DecryptFinal(ctx, s->buf, &outl);
	res += outl;

	return res;
}

void blob_print_and_strip_padding(struct blob *s, size_t offset) {
	uint8_t maybe_pad = (uint8_t)s->buf[s->len - 1];

	if (maybe_pad <= 0x10) {
		s->buf[s->len - maybe_pad] = 0x00;
		blob_print(s, offset);
		s->buf[s->len - maybe_pad] = maybe_pad;
	} else {
		blob_print(s, offset);
	}

}

void blob_print_hex(struct blob *s)
{
	uint8_t *hex_rep = blob_to_hex(s);
	printf("%s\n", hex_rep);
	free(hex_rep);
}

void blob_print_ascii(struct blob *s)
{
	for (size_t k = 0; k < s->len; k++) {
		if (s->buf[k] > 0x7f || s->buf[k] < 0x20)
			putchar('-');
		else
			putchar((char)s->buf[k]);
	}
	putchar('\n');
}

void blob_print(struct blob *s, size_t offset)
{
	printf("%.*s\n", (int)(s->len - offset), s->buf + offset);
}

int blob_validate_pkcs7(struct blob *blob)
{
	if (blob->len % AES_BLK_SZ || blob->len < 1)
		return 0;

	uint8_t padding_byte = blob->buf[blob->len - 1];
	if (padding_byte > 0x10 || padding_byte == 0x00)
		return 0;

	for (size_t k = 1; k < padding_byte; k++)
		if ((uint8_t)blob->buf[blob->len - 1 - k] != padding_byte)
			return 0;

	return 1;
}

static struct blob *generate_keystream_block(struct blob *key,
						uint64_t nonce, size_t ctr)
{
	uint8_t keystream_raw[16] = { 0 };

	// This does a little endian copy on my Intel chip
	memcpy(keystream_raw, (uint8_t *)&nonce, 8);
	memcpy(&keystream_raw[8], &ctr, 8);
	struct blob *keystream = blob_from_buf(keystream_raw, 16);
	blob_encrypt_aes_ecb(keystream, key);

	return keystream;
}

void blob_edit_aes_ctr(struct blob *key,
		struct blob *msg, size_t offset, struct blob *edit)
{
	struct blob *keystream;
	uint64_t nonce = 0;
	uint64_t ctr = offset / 16;
	//
	// `bndry` keeps track of the encryption boundary; indices less
	// than bndry have already been processed.
	//
	size_t bndry = offset;

	for (;;) {
		keystream = generate_keystream_block(key, nonce, (size_t)ctr);

		do {
			msg->buf[bndry] = keystream->buf[bndry % 16]
						^ edit->buf[bndry - offset];
			bndry++;
		} while (bndry % 16
			&& bndry < msg->len
			&& bndry < edit->len + offset); // omg overflow yikes

		ctr++;
		free(keystream);

		if (bndry == msg->len || bndry - offset == edit->len)
			break;
	}
}

void blob_do_aes_ctr(struct blob *msg, struct blob *key)
{
	struct blob *keystream;
	uint64_t nonce = 0;
	uint64_t ctr = 0;
	size_t mask_head = 0;

	while (mask_head != msg->len) {
		keystream = generate_keystream_block(key, nonce, (size_t)ctr);

		size_t remaining = msg->len - mask_head;
		xor_buffers(msg->buf + mask_head, keystream->buf,
			remaining > AES_BLK_SZ ? AES_BLK_SZ : remaining);
		mask_head += remaining < AES_BLK_SZ ? remaining : AES_BLK_SZ;

		free(keystream);
		ctr++;
	}
}

void blob_write(struct blob *buf, int fd)
{
	size_t total = buf->len;
	uint8_t *p = buf->buf;

	do {
		p += write(fd, p, total - (p - buf->buf));
	} while (p - buf->buf < total);
}
