#ifndef MAGNUS_COMPRESSION_H
#define MAGNUS_COMPRESSION_H

#include <stdbool.h>
#include <stddef.h>

#define MAGNUS_COMPRESSION_MIN_SIZE 256
#define MAGNUS_COMPRESSION_MAX_SIZE (8 * 1024 * 1024)

bool magnus_accepts_gzip(const char *accept_encoding);
bool magnus_content_type_compressible(const char *content_type);
int magnus_gzip_compress(const unsigned char *input, size_t input_length,
                         unsigned char **output, size_t *output_length);

#endif
