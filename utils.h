#ifndef UTILS_H
#define UTILS_H

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "blob.h"

void xor_buffers(uint8_t *a, uint8_t *b, size_t len);

void bytes_to_hex(uint8_t *in, size_t len, uint8_t *out);
int hex_to_bytes(uint8_t *str, uint8_t *buf);

size_t bytes_to_b64(uint8_t *out, uint8_t *in, size_t len);
size_t b64_to_bytes(uint8_t *out, uint8_t *in, size_t len);

size_t distance_hamming(uint8_t *a, uint8_t *b, size_t n);

int blocks_eq(uint8_t *a, uint8_t *b, size_t len);

#endif
