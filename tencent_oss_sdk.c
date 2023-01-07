/**************************************************************************
 * Copyright (C) 2022-2023  Junlon2006
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 **************************************************************************/
#include "tencent_oss_sdk.h"
#include "webclient.h"

#include <stdint.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#define MD5SUM_SIZE  (16)

static const char *g_s_wday[] = {
  "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
};

static const char *g_s_mon[] = {
  "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

/**
 * @brief need porting to other OS
 *
 * @param date
 * @param len
 */
static void __get_gmt(char *date, int len, time_t *ts)
{
  struct tm *tm;

  /* step1. get gmt */
  time(ts);
  tm = gmtime(ts);

  /* step2. format gmt */
  snprintf(date, len, "%s, %.2d %s %.4d %.2d:%.2d:%.2d GMT",
           g_s_wday[tm->tm_wday], tm->tm_mday, g_s_mon[tm->tm_mon],
           1900 + tm->tm_year, tm->tm_hour, tm->tm_min, tm->tm_sec);
}

static void __base64_encode(const uint8_t *src, int32_t src_len, char *encoded)
{
  const char basis_64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  int i;
  char *p = encoded;
  for (i = 0; i < src_len - 2; i += 3) {
    *p++ = basis_64[(src[i] >> 2) & 0x3F];
    *p++ = basis_64[((src[i] & 0x3) << 4) |
      ((src[i + 1] & 0xF0) >> 4)];
    *p++ = basis_64[((src[i + 1] & 0xF) << 2) |
      ((src[i + 2] & 0xC0) >> 6)];
    *p++ = basis_64[src[i + 2] & 0x3F];
  }

  if (i < src_len) {
    *p++ = basis_64[(src[i] >> 2) & 0x3F];
    if (i == (src_len - 1)) {
      *p++ = basis_64[((src[i] & 0x3) << 4)];
      *p++ = '=';
    } else {
      *p++ = basis_64[((src[i] & 0x3) << 4) |
        ((src[i + 1] & 0xF0) >> 4)];
      *p++ = basis_64[((src[i + 1] & 0xF) << 2)];
    }
    *p++ = '=';
  }

  *p++ = '\0';
}

typedef struct {
  uint64_t size;        // Size of input in bytes
  uint32_t buffer[4];   // Current accumulation of hash
  uint8_t input[64];    // Input to be used in the next step
  uint8_t digest[16];   // Result of algorithm
} md5_context_t;

/*
 * Derived from the RSA Data Security, Inc. MD5 Message-Digest Algorithm
 * and modified slightly to be functionally identical but condensed into control structures.
 */

/*
 * Constants defined by the MD5 algorithm
 */
#define MD5_A 0x67452301
#define MD5_B 0xefcdab89
#define MD5_C 0x98badcfe
#define MD5_D 0x10325476

static uint32_t MD5_S[] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                           5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
                           4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                           6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

static uint32_t MD5_K[] = {0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
                           0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
                           0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
                           0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
                           0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
                           0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
                           0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
                           0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
                           0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
                           0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
                           0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
                           0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
                           0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
                           0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
                           0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
                           0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};
/*
 * Bit-manipulation functions defined by the MD5 algorithm
 */
#define MD5_F(X, Y, Z) ((X & Y) | (~X & Z))
#define MD5_G(X, Y, Z) ((X & Z) | (Y & ~Z))
#define MD5_H(X, Y, Z) (X ^ Y ^ Z)
#define MD5_I(X, Y, Z) (Y ^ (X | ~Z))

/*
 * Padding used to make the size (in bits) of the input congruent to 448 mod 512
 */
static uint8_t PADDING[] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
/*
 * Initialize a context
 */
static void __md5_init(md5_context_t *ctx)
{
  ctx->size = (uint64_t)0;
  ctx->buffer[0] = (uint32_t)MD5_A;
  ctx->buffer[1] = (uint32_t)MD5_B;
  ctx->buffer[2] = (uint32_t)MD5_C;
  ctx->buffer[3] = (uint32_t)MD5_D;
}

/*
 * Rotates a 32-bit word left by n bits
 */
static uint32_t __rotate_left(uint32_t x, uint32_t n)
{
  return (x << n) | (x >> (32 - n));
}

/*
 * Step on 512 bits of input with the main MD5 algorithm.
 */
static void __md5_step(uint32_t *buffer, uint32_t *input)
{
  uint32_t AA = buffer[0];
  uint32_t BB = buffer[1];
  uint32_t CC = buffer[2];
  uint32_t DD = buffer[3];
  uint32_t E;
  unsigned int j;

  for (int i = 0; i < 64; ++i) {
    switch (i / 16) {
      case 0:
        E = MD5_F(BB, CC, DD);
        j = i;
        break;
      case 1:
        E = MD5_G(BB, CC, DD);
        j = ((i * 5) + 1) % 16;
        break;
      case 2:
        E = MD5_H(BB, CC, DD);
        j = ((i * 3) + 5) % 16;
        break;
      default:
        E = MD5_I(BB, CC, DD);
        j = (i * 7) % 16;
        break;
    }

    uint32_t temp = DD;
    DD = CC;
    CC = BB;
    BB = BB + __rotate_left(AA + E + MD5_K[i] + input[j], MD5_S[i]);
    AA = temp;
  }

  buffer[0] += AA;
  buffer[1] += BB;
  buffer[2] += CC;
  buffer[3] += DD;
}

/*
 * Add some amount of input to the context
 *
 * If the input fills out a block of 512 bits, apply the algorithm (__md5_step)
 * and save the result in the buffer. Also updates the overall size.
 */
static void __md5_update(md5_context_t *ctx, uint8_t *input_buffer, size_t input_len)
{
  uint32_t input[16];
  unsigned int offset = ctx->size % 64;
  ctx->size += (uint64_t)input_len;

  // Copy each byte in input_buffer into the next space in our context input
  for (unsigned int i = 0; i < input_len; ++i) {
    ctx->input[offset++] = (uint8_t)*(input_buffer + i);

    // If we've filled our context input, copy it into our local array input
    // then reset the offset to 0 and fill in a new buffer.
    // Every time we fill out a chunk, we run it through the algorithm
    // to enable some back and forth between cpu and i/o
    if (offset % 64 == 0) {
      for (unsigned int j = 0; j < 16; ++j) {
        // Convert to little-endian
        // The local variable `input` our 512-bit chunk separated into 32-bit words
        // we can use in calculations
        input[j] = (uint32_t)(ctx->input[(j * 4) + 3]) << 24 |
          (uint32_t)(ctx->input[(j * 4) + 2]) << 16 |
          (uint32_t)(ctx->input[(j * 4) + 1]) <<  8 |
          (uint32_t)(ctx->input[(j * 4)]);
      }
      __md5_step(ctx->buffer, input);
      offset = 0;
    }
  }
}

/*
 * Pad the current input to get to 448 bytes, append the size in bits to the very end,
 * and save the result of the final iteration into digest.
 */
static void __md5_finalize(md5_context_t *ctx)
{
  uint32_t input[16];
  unsigned int offset = ctx->size % 64;
  unsigned int padding_length = offset < 56 ? 56 - offset : (56 + 64) - offset;

  // Fill in the padding andndo the changes to size that resulted from the update
  __md5_update(ctx, PADDING, padding_length);
  ctx->size -= (uint64_t)padding_length;

  // Do a final update (internal to this function)
  // Last two 32-bit words are the two halves of the size (converted from bytes to bits)
  for (unsigned int j = 0; j < 14; ++j) {
    input[j] = (uint32_t)(ctx->input[(j * 4) + 3]) << 24 |
      (uint32_t)(ctx->input[(j * 4) + 2]) << 16 |
      (uint32_t)(ctx->input[(j * 4) + 1]) <<  8 |
      (uint32_t)(ctx->input[(j * 4)]);
  }
  input[14] = (uint32_t)(ctx->size * 8);
  input[15] = (uint32_t)((ctx->size * 8) >> 32);

  __md5_step(ctx->buffer, input);

  // Move the result into digest (convert from little-endian)
  for (unsigned int i = 0; i < 4; ++i) {
    ctx->digest[(i * 4) + 0] = (uint8_t)((ctx->buffer[i] & 0x000000FF));
    ctx->digest[(i * 4) + 1] = (uint8_t)((ctx->buffer[i] & 0x0000FF00) >>  8);
    ctx->digest[(i * 4) + 2] = (uint8_t)((ctx->buffer[i] & 0x00FF0000) >> 16);
    ctx->digest[(i * 4) + 3] = (uint8_t)((ctx->buffer[i] & 0xFF000000) >> 24);
  }
}

/*
 * Functions that will return a pointer to the hash of the provided input
 */
static void __md5_sum(uint8_t *input, int len, uint8_t sum[MD5SUM_SIZE])
{
  md5_context_t ctx;
  __md5_init(&ctx);
  __md5_update(&ctx, input, len);
  __md5_finalize(&ctx);
  memcpy(sum, ctx.digest, MD5SUM_SIZE);
}

typedef struct {
  /** message digest */
  unsigned int digest[5];
  /** 64-bit bit counts */
  unsigned int count_lo, count_hi;
  /** SHA data buffer */
  unsigned int data[16];
  /** unprocessed amount in data */
  int local;
} oss_sha1_ctx_t;

static void __oss_sha1_init(oss_sha1_ctx_t *sha_info)
{
  sha_info->digest[0] = 0x67452301L;
  sha_info->digest[1] = 0xefcdab89L;
  sha_info->digest[2] = 0x98badcfeL;
  sha_info->digest[3] = 0x10325476L;
  sha_info->digest[4] = 0xc3d2e1f0L;
  sha_info->count_lo  = 0L;
  sha_info->count_hi  = 0L;
  sha_info->local     = 0;
}

union endian_test {
  long Long;
  char Char[sizeof(long)];
};

static char __is_little_endian(void)
{
  static union endian_test u;
  u.Long = 1;
  return (u.Char[0] == 1);
}

static void __maybe_byte_reverse(unsigned int *buffer, int count)
{
  int i;
  unsigned char ct[4], *cp;

  if (__is_little_endian()) {	/* do the swap only if it is little endian */
    count /= sizeof(unsigned int);
    cp = (unsigned char *)buffer;
    for (i = 0; i < count; ++i) {
      ct[0] = cp[0];
      ct[1] = cp[1];
      ct[2] = cp[2];
      ct[3] = cp[3];
      cp[0] = ct[3];
      cp[1] = ct[2];
      cp[2] = ct[1];
      cp[3] = ct[0];
      cp += sizeof(unsigned int);
    }
  }
}

#define f1(x,y,z)               ((x & y) | (~x & z))
#define f2(x,y,z)               (x ^ y ^ z)
#define f3(x,y,z)               ((x & y) | (x & z) | (y & z))
#define f4(x,y,z)               (x ^ y ^ z)

#define CONST1                  0x5a827999L
#define CONST2                  0x6ed9eba1L
#define CONST3                  0x8f1bbcdcL
#define CONST4                  0xca62c1d6L

#define OSS_SHA1_DIGESTSIZE     20
#define SHA_BLOCKSIZE           64
#define ROT32(x,n)              ((x << n) | (x >> (32 - n)))

#define FUNC(n,i)               temp = ROT32(A,5) + f##n(B,C,D) + E + W[i] + CONST##n; \
                                E = D; D = C; C = ROT32(B,30); B = A; A = temp

static void __sha_transform(oss_sha1_ctx_t *sha_info)
{
  int i;
  unsigned int temp, A, B, C, D, E, W[80];

  for (i = 0; i < 16; ++i) {
    W[i] = sha_info->data[i];
  }

  for (i = 16; i < 80; ++i) {
    W[i] = W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16];
    W[i] = ROT32(W[i], 1);
  }

  A = sha_info->digest[0];
  B = sha_info->digest[1];
  C = sha_info->digest[2];
  D = sha_info->digest[3];
  E = sha_info->digest[4];

  FUNC(1, 0);  FUNC(1, 1);  FUNC(1, 2);  FUNC(1, 3);  FUNC(1, 4);
  FUNC(1, 5);  FUNC(1, 6);  FUNC(1, 7);  FUNC(1, 8);  FUNC(1, 9);
  FUNC(1,10);  FUNC(1,11);  FUNC(1,12);  FUNC(1,13);  FUNC(1,14);
  FUNC(1,15);  FUNC(1,16);  FUNC(1,17);  FUNC(1,18);  FUNC(1,19);

  FUNC(2,20);  FUNC(2,21);  FUNC(2,22);  FUNC(2,23);  FUNC(2,24);
  FUNC(2,25);  FUNC(2,26);  FUNC(2,27);  FUNC(2,28);  FUNC(2,29);
  FUNC(2,30);  FUNC(2,31);  FUNC(2,32);  FUNC(2,33);  FUNC(2,34);
  FUNC(2,35);  FUNC(2,36);  FUNC(2,37);  FUNC(2,38);  FUNC(2,39);

  FUNC(3,40);  FUNC(3,41);  FUNC(3,42);  FUNC(3,43);  FUNC(3,44);
  FUNC(3,45);  FUNC(3,46);  FUNC(3,47);  FUNC(3,48);  FUNC(3,49);
  FUNC(3,50);  FUNC(3,51);  FUNC(3,52);  FUNC(3,53);  FUNC(3,54);
  FUNC(3,55);  FUNC(3,56);  FUNC(3,57);  FUNC(3,58);  FUNC(3,59);

  FUNC(4,60);  FUNC(4,61);  FUNC(4,62);  FUNC(4,63);  FUNC(4,64);
  FUNC(4,65);  FUNC(4,66);  FUNC(4,67);  FUNC(4,68);  FUNC(4,69);
  FUNC(4,70);  FUNC(4,71);  FUNC(4,72);  FUNC(4,73);  FUNC(4,74);
  FUNC(4,75);  FUNC(4,76);  FUNC(4,77);  FUNC(4,78);  FUNC(4,79);

  sha_info->digest[0] += A;
  sha_info->digest[1] += B;
  sha_info->digest[2] += C;
  sha_info->digest[3] += D;
  sha_info->digest[4] += E;
}

static void __oss_sha1_update_binary(oss_sha1_ctx_t *sha_info,
                                     const unsigned char *buffer, unsigned int count)
{
  unsigned int i;

  if ((sha_info->count_lo + ((unsigned int) count << 3)) < sha_info->count_lo) {
    ++sha_info->count_hi;
  }

  sha_info->count_lo += (unsigned int) count << 3;
  sha_info->count_hi += (unsigned int) count >> 29;

  if (sha_info->local) {
    i = SHA_BLOCKSIZE - sha_info->local;
    if (i > count) {
      i = count;
    }

    memcpy(((char *) sha_info->data) + sha_info->local, buffer, i);
    count -= i;
    buffer += i;
    sha_info->local += i;
    if (sha_info->local == SHA_BLOCKSIZE) {
      __maybe_byte_reverse(sha_info->data, SHA_BLOCKSIZE);
      __sha_transform(sha_info);
    } else {
      return;
    }
  }

  while (count >= SHA_BLOCKSIZE) {
    memcpy(sha_info->data, buffer, SHA_BLOCKSIZE);
    buffer += SHA_BLOCKSIZE;
    count -= SHA_BLOCKSIZE;
    __maybe_byte_reverse(sha_info->data, SHA_BLOCKSIZE);
    __sha_transform(sha_info);
  }

  memcpy(sha_info->data, buffer, count);
  sha_info->local = count;
}

static void __oss_sha1_update(oss_sha1_ctx_t *sha_info, const char *buf, unsigned int count)
{
  __oss_sha1_update_binary(sha_info, (const unsigned char *) buf, count);
}

static void __oss_sha1_final(unsigned char digest[OSS_SHA1_DIGESTSIZE], oss_sha1_ctx_t *sha_info)
{
  int count, i, j;
  unsigned int lo_bit_count, hi_bit_count, k;

  lo_bit_count = sha_info->count_lo;
  hi_bit_count = sha_info->count_hi;
  count = (int) ((lo_bit_count >> 3) & 0x3f);
  ((unsigned char *) sha_info->data)[count++] = 0x80;

  if (count > SHA_BLOCKSIZE - 8) {
    memset(((unsigned char *) sha_info->data) + count, 0, SHA_BLOCKSIZE - count);
    __maybe_byte_reverse(sha_info->data, SHA_BLOCKSIZE);
    __sha_transform(sha_info);
    memset((unsigned char *) sha_info->data, 0, SHA_BLOCKSIZE - 8);
  } else {
    memset(((unsigned char *) sha_info->data) + count, 0, SHA_BLOCKSIZE - 8 - count);
  }

  __maybe_byte_reverse(sha_info->data, SHA_BLOCKSIZE);
  sha_info->data[14] = hi_bit_count;
  sha_info->data[15] = lo_bit_count;
  __sha_transform(sha_info);

  for (i = 0, j = 0; j < OSS_SHA1_DIGESTSIZE; i++) {
    k = sha_info->digest[i];
    digest[j++] = (unsigned char) ((k >> 24) & 0xff);
    digest[j++] = (unsigned char) ((k >> 16) & 0xff);
    digest[j++] = (unsigned char) ((k >> 8) & 0xff);
    digest[j++] = (unsigned char) (k & 0xff);
  }
}

static void __get_hex_from_digest(unsigned char hexdigest[OSS_SHA1_DIGESTSIZE << 1],
                                  unsigned char digest[OSS_SHA1_DIGESTSIZE])
{
  unsigned char hex_digits[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                  '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  int j = 0;
  int i = 0;

  for (; i < 20; i++) {
    hexdigest[j++] = hex_digits[(digest[i] >> 4) & 0x0f];
    hexdigest[j++] = hex_digits[digest[i] & 0x0f];
  }
}

static void __get_sha1_hexdigest(unsigned char hexdigest[OSS_SHA1_DIGESTSIZE << 1], const unsigned char *message, int message_len)
{
  unsigned char digest[OSS_SHA1_DIGESTSIZE];
  oss_sha1_ctx_t context;
  __oss_sha1_init(&context);
  __oss_sha1_update(&context, (const char *)message, (unsigned int)message_len);
  __oss_sha1_final(digest, &context);
  __get_hex_from_digest(hexdigest, digest);
}

static void __hmac_sha1(unsigned char hmac[OSS_SHA1_DIGESTSIZE], const unsigned char *key, int key_len,
                        const unsigned char *message, int message_len)
{
  unsigned char kopad[64], kipad[64];
  int i;
  unsigned char digest[OSS_SHA1_DIGESTSIZE];
  oss_sha1_ctx_t context;

  if (key_len > 64) {
    key_len = 64;
  }

  for (i = 0; i < key_len; i++) {
    kopad[i] = key[i] ^ 0x5c;
    kipad[i] = key[i] ^ 0x36;
  }

  for (; i < 64; i++) {
    kopad[i] = 0 ^ 0x5c;
    kipad[i] = 0 ^ 0x36;
  }

  __oss_sha1_init(&context);
  __oss_sha1_update(&context, (const char *)kipad, 64);
  __oss_sha1_update(&context, (const char *)message, (unsigned int)message_len);
  __oss_sha1_final(digest, &context);

  __oss_sha1_init(&context);
  __oss_sha1_update(&context, (const char *)kopad, 64);
  __oss_sha1_update(&context, (const char *)digest, 20);
  __oss_sha1_final(hmac, &context);
}

static void __get_hmac_sha1_hexdigest(unsigned char hexdigest[OSS_SHA1_DIGESTSIZE << 1],
                                      const unsigned char *key, int key_len,
                                      const unsigned char *message, int message_len)
{
  unsigned char hmac[OSS_SHA1_DIGESTSIZE];
  __hmac_sha1(hmac, key, key_len, message, message_len);
  __get_hex_from_digest(hexdigest, hmac);
}

static void __get_content_md5sum(const char *data, int len, uint8_t sum[MD5SUM_SIZE])
{
  __md5_sum((uint8_t *)data, len, sum);
}

static void __get_content_md5_base64(const uint8_t sum[MD5SUM_SIZE], char *base64_out)
{
  __base64_encode(sum, MD5SUM_SIZE, base64_out);
}

static void __get_url_encode(char *dst, char *src)
{
  char c;
  while ((c = *src++) != '\0') {
    if (c == '=') {
      *dst++ = '%';
      *dst++ = '3';
      *dst++ = 'D';
    } else if (c == '/') {
      *dst++ = '%';
      *dst++ = '2';
      *dst++ = 'F';
    } else if (c == '+') {
      *dst++ = '%';
      *dst++ = '2';
      *dst++ = 'B';
    } else {
      *dst++ = c;
    }
  }
  *dst = '\0';
}

#define FMT_STR_LEN (2048)
static char* __get_fmt_str(const char *obj_name,
                           const char *content_md5_base64,
                           const char *host,
                           const char *token)
{
  char url_encoded[MD5SUM_SIZE << 2];
  char* fmt_str = (char *)malloc(FMT_STR_LEN);
  assert(fmt_str);
  __get_url_encode(url_encoded, (char *)content_md5_base64);
  snprintf(fmt_str, FMT_STR_LEN,
           "put\n"
           "/%s\n"
           "\n"
           "content-md5=%s&content-type=application%%2Foctet-stream&host=%s&x-cos-security-token=%s\n",
           obj_name, url_encoded, host, token);
  return fmt_str;
}

static void __get_time_str(char *time_str, int len, time_t ts)
{
  snprintf(time_str, len, "%lld;%lld", (long long)ts, (long long)ts + 300LL);
}

static void __get_sign_str(char *sig_str, int len,
                           const char *time_str,
                           unsigned char hexdigest[40])
{
  snprintf(sig_str, len,
           "sha1\n"
           "%s\n"
           "%.*s\n", time_str, 40, hexdigest);
}

static void __get_auth(char *auth, int len,
                       const char *access_key_id, const char *access_key_secret,
                       const char *obj_name, const char *content_md5_base64,
                       time_t ts, const char *host, const char *token)
{
  char time_str[32];
  unsigned char hexdigest[40];
  unsigned char sign_key[40];
  char sig_str[256];
  char *fmt_str;

  fmt_str = __get_fmt_str(obj_name, content_md5_base64, host, token);
  __get_sha1_hexdigest(hexdigest, (const unsigned char *)fmt_str, strlen(fmt_str));
  __get_time_str(time_str, sizeof(time_str), ts);
  __get_sign_str(sig_str, sizeof(sig_str), time_str, hexdigest);
  __get_hmac_sha1_hexdigest(sign_key,
                            (const unsigned char *)access_key_secret, strlen(access_key_secret),
                            (const unsigned char *)time_str, strlen(time_str));
  __get_hmac_sha1_hexdigest(hexdigest, (const unsigned char *)sign_key, sizeof(sign_key),
                            (const unsigned char *)sig_str, strlen(sig_str));
  snprintf(auth, len,
           "q-sign-algorithm=sha1&"
           "q-ak=%s&"
           "q-sign-time=%s&"
           "q-key-time=%s&"
           "q-header-list=%s&"
           "q-url-param-list=%s&"
           "q-signature=%.*s",
           access_key_id, time_str, time_str, "content-md5;content-type;host;x-cos-security-token", "",
           (int)sizeof(hexdigest), hexdigest);
  free(fmt_str);
}

static void __get_host(char *host, int len, const char *bucket_name, const char *region)
{
  snprintf(host, len, "%s.cos.%s.myqcloud.com", bucket_name, region);
}

static int __http_put(const char *data, int len, const char *object_name,
                      const char *bucket_name, const char *region, const char *access_key_id,
                      const char *access_key_secret, const char *token)
{
  webclient_session *session = NULL;
  char uri[256]; /* 256 byte must be enough */
  uint8_t content_md5[MD5SUM_SIZE];
  char content_md5_base64[MD5SUM_SIZE << 2];
  char gtm[64];
  time_t unix_timestamp;
  char auth[512];
  char host[128];

  /* step1. create webclient session */
  session = webclient_session_create(2048, "cert", 4);
  assert(session);

  __get_host(host, sizeof(host), bucket_name, region);
  __get_content_md5sum(data, len, content_md5);
  __get_content_md5_base64(content_md5, content_md5_base64);
  __get_gmt(gtm, sizeof(gtm), &unix_timestamp);
  __get_auth(auth, sizeof(auth), access_key_id, access_key_secret, object_name, content_md5_base64, unix_timestamp, host, token);

  /* step2. fill http header */
  webclient_header_fields_add(session, "Host: %s\r\n", host);
  webclient_header_fields_add(session, "User-Agent: cos-sdk-c/5.0.14(Compatible Unknown)\r\n");
  webclient_header_fields_add(session, "Accept: */*\r\n");
  webclient_header_fields_add(session, "Content-Length: %d\r\n", len);
  webclient_header_fields_add(session, "Content-Type: application/octet-stream\r\n");
  webclient_header_fields_add(session, "Content-MD5: %s\r\n", content_md5_base64);
  webclient_header_fields_add(session, "Date: %s\r\n", gtm);
  webclient_header_fields_add(session, "Authorization: %s\r\n", auth);
  webclient_header_fields_add(session, "x-cos-security-token: %s\r\n", token);

  /* step3. URI generate */
  snprintf(uri, sizeof(uri), "http://%s/%s", host, object_name);

  /* step4. http put request */
  int err = webclient_put(session, uri, data, len);

  /* step5. destroy webclient */
  webclient_close(session);
  return err;
}

int tencent_oss_push(const char *data, int len, const char *object_name,
                     const char *bucket_name, const char *region,
                     const char *access_key_id, const char *access_key_secret, const char *token)
{
  int err = __http_put(data, len, object_name, bucket_name, region, access_key_id, access_key_secret, token);
  return err == 200 ? 0 : -1;
}
