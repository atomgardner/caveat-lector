#ifndef SLICE_H
#define SLICE_H

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

struct blob {
	size_t len;
	uint8_t *buf;
#if blob_v2
	FILE *f;
# else
	size_t cap;
#endif
};

void blob_init(struct blob *buf, size_t hint);
void blob_init_rand(struct blob *s, size_t len);
void blob_add(struct blob *buf, const uint8_t *str, size_t len);
void blob_add_slice(struct blob *a, struct blob *b);
void blob_add_byte(struct blob *, uint8_t, size_t);

struct blob *blob_from_buf(uint8_t *buf, size_t len);
int blob_from_file(struct blob *a, char *path);
int blob_from_hex(struct blob *a, uint8_t *str);

ssize_t blob_contains(struct blob *s, uint8_t b);

void blob_free(struct blob *buf);
void blob_reset(struct blob *buf);

void blob_grow(struct blob *s, size_t delta);

void blob_xor_buf(struct blob *a, uint8_t *b, size_t len);
void blob_xor_mask(struct blob *s, uint8_t c);
void blob_xor_mask_repeating(struct blob *plain, struct blob *key);

int blob_decode_hex(struct blob *a);
int blob_decode_b64(struct blob *a);
uint8_t *blob_to_b64(struct blob *a);
uint8_t *blob_to_hex(struct blob *a);

int blob_split(struct blob ***l, struct blob *a, char delim);
struct blob *blob_take_every_nth(struct blob *a, size_t nth, size_t offset);
void blob_release(struct blob *s);
int blob_split_and_join(struct blob *sli, char delim);

void blob_pad_pkcs7(struct blob *a, size_t blk_len);

size_t blob_encrypt_aes_ecb(struct blob *s, struct blob *key);
size_t blob_decrypt_aes_ecb(struct blob *s, struct blob *key);

size_t blob_decrypt_aes_cbc(struct blob *s, struct blob *key, struct blob *iv);
size_t blob_encrypt_aes_cbc(struct blob *s, struct blob *key, struct blob *iv);

size_t blob_encrypt_aes_ctr(struct blob *msg, struct blob *key);
size_t blob_decrypt_aes_ctr(struct blob *msg, struct blob *key);
void blob_do_aes_ctr(struct blob *msg, struct blob *key);
void blob_edit_aes_ctr(struct blob *key, struct blob *msg, size_t offset, struct blob *edit);

void blob_print(struct blob *s, size_t offset);
void blob_print_hex(struct blob *s);
void blob_print_ascii(struct blob *s);
void blob_print_and_strip_padding(struct blob *s, size_t offset);
int blob_validate_pkcs7(struct blob *s);

void blob_write(struct blob *buf, int fd);

#endif
