#include "gradm.h"

/* digest-sha256.c,v 1.13 2002/10/02 22:02:08 hvr Exp $
 *
 * SHA-256 code by Jean-Luc Cooke <jlcooke@certainkey.com>.
 * 
 * Glue code originally by Andrew McDonald and Alan Smithee, mailed
 * to maintainer on pulped trees.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 */

typedef struct {
	u_int32_t state[8];
	u_int32_t count[2];
	u_int8_t buf[128];
} sha256_ctx_t;

static __inline__ u_int32_t
generic_rotr32(const u_int32_t x, const unsigned bits)
{
	const unsigned n = bits % 32;
	return (x >> n) | (x << (32 - n));
}

#define Ch(x,y,z)   ((x & y) ^ (~x & z))
#define Maj(x,y,z)  ((x & y) ^ ( x & z) ^ (y & z))
#define RORu32(x,y) generic_rotr32(x, y)
#define e0(x)       (RORu32(x, 2) ^ RORu32(x,13) ^ RORu32(x,22))
#define e1(x)       (RORu32(x, 6) ^ RORu32(x,11) ^ RORu32(x,25))
#define s0(x)       (RORu32(x, 7) ^ RORu32(x,18) ^ (x >> 3))
#define s1(x)       (RORu32(x,17) ^ RORu32(x,19) ^ (x >> 10))

#define H0         0x6a09e667
#define H1         0xbb67ae85
#define H2         0x3c6ef372
#define H3         0xa54ff53a
#define H4         0x510e527f
#define H5         0x9b05688c
#define H6         0x1f83d9ab
#define H7         0x5be0cd19

static const u_int32_t sha256_K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define LOAD_OP(I)\
 {\
  t1  = input[(4*I)  ] & 0xff; t1<<=8;\
  t1 |= input[(4*I)+1] & 0xff; t1<<=8;\
  t1 |= input[(4*I)+2] & 0xff; t1<<=8;\
  t1 |= input[(4*I)+3] & 0xff;\
  W[I] = t1;\
 }

#define BLEND_OP(I) W[I] = s1(W[I-2]) + W[I-7] + s0(W[I-15]) + W[I-16];

static void
SHA256Transform(u_int32_t * state, const u_int8_t * input)
{
	u_int32_t a, b, c, d, e, f, g, h, t1, t2;
	u_int32_t W[64];

	int i;

	/* load the input */
	LOAD_OP(0);
	LOAD_OP(1);
	LOAD_OP(2);
	LOAD_OP(3);
	LOAD_OP(4);
	LOAD_OP(5);
	LOAD_OP(6);
	LOAD_OP(7);
	LOAD_OP(8);
	LOAD_OP(9);
	LOAD_OP(10);
	LOAD_OP(11);
	LOAD_OP(12);
	LOAD_OP(13);
	LOAD_OP(14);
	LOAD_OP(15);

	/* now blend */
	for (i = 16; i < 64; i += 8) {
		BLEND_OP(i);
		BLEND_OP(i + 1);
		BLEND_OP(i + 2);
		BLEND_OP(i + 3);
		BLEND_OP(i + 4);
		BLEND_OP(i + 5);
		BLEND_OP(i + 6);
		BLEND_OP(i + 7);
	}

	/* load the state into our registers */
	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];
	f = state[5];
	g = state[6];
	h = state[7];

	/* now iterate */
	for (i = 0; i < 64; i += 8) {
		t1 = h + e1(e) + Ch(e, f, g) + sha256_K[i] + W[i];
		t2 = e0(a) + Maj(a, b, c);
		d += t1;
		h = t1 + t2;
		t1 = g + e1(d) + Ch(d, e, f) + sha256_K[i + 1] + W[i + 1];
		t2 = e0(h) + Maj(h, a, b);
		c += t1;
		g = t1 + t2;
		t1 = f + e1(c) + Ch(c, d, e) + sha256_K[i + 2] + W[i + 2];
		t2 = e0(g) + Maj(g, h, a);
		b += t1;
		f = t1 + t2;
		t1 = e + e1(b) + Ch(b, c, d) + sha256_K[i + 3] + W[i + 3];
		t2 = e0(f) + Maj(f, g, h);
		a += t1;
		e = t1 + t2;
		t1 = d + e1(a) + Ch(a, b, c) + sha256_K[i + 4] + W[i + 4];
		t2 = e0(e) + Maj(e, f, g);
		h += t1;
		d = t1 + t2;
		t1 = c + e1(h) + Ch(h, a, b) + sha256_K[i + 5] + W[i + 5];
		t2 = e0(d) + Maj(d, e, f);
		g += t1;
		c = t1 + t2;
		t1 = b + e1(g) + Ch(g, h, a) + sha256_K[i + 6] + W[i + 6];
		t2 = e0(c) + Maj(c, d, e);
		f += t1;
		b = t1 + t2;
		t1 = a + e1(f) + Ch(f, g, h) + sha256_K[i + 7] + W[i + 7];
		t2 = e0(b) + Maj(b, c, d);
		e += t1;
		a = t1 + t2;
	}

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	state[5] += f;
	state[6] += g;
	state[7] += h;

	/* clear any sensitive info... */
	a = b = c = d = e = f = g = h = t1 = t2 = 0;
	memset(W, 0, 64 * sizeof (u_int32_t));
}

static void
SHA256Init(sha256_ctx_t * C)
{
	C->state[0] = H0;
	C->state[1] = H1;
	C->state[2] = H2;
	C->state[3] = H3;
	C->state[4] = H4;
	C->state[5] = H5;
	C->state[6] = H6;
	C->state[7] = H7;
	C->count[0] = C->count[1] = 0;
	memset(C->buf, 0, 128);
}

static void
SHA256Update(sha256_ctx_t * C, const u_int8_t * input, u_int32_t inputLen)
{
	u_int32_t i, index, partLen;

	/* Compute number of bytes mod 128 */
	index = (u_int32_t) ((C->count[0] >> 3) & 0x3f);

	/* Update number of bits */
	if ((C->count[0] += (inputLen << 3)) < (inputLen << 3)) {
		C->count[1]++;
		C->count[1] += (inputLen >> 29);
	}

	partLen = 64 - index;

	/* Transform as many times as possible. */
	if (inputLen >= partLen) {
		memcpy(&C->buf[index], input, partLen);
		SHA256Transform(C->state, C->buf);

		for (i = partLen; i + 63 < inputLen; i += 64)
			SHA256Transform(C->state, &input[i]);
		index = 0;
	} else {
		i = 0;
	}

	/* Buffer remaining input */
	memcpy(&C->buf[index], &input[i], inputLen - i);
}

static void
SHA256Final(sha256_ctx_t * C, u_int8_t * digest)
{
	static const u_int8_t padding[64] = { 0x80, };
	u_int8_t bits[8];
	u_int32_t t, index, padLen;
	int i, j;

	/* Save number of bits */
	t = C->count[0];
	bits[7] = t;
	t >>= 8;
	bits[6] = t;
	t >>= 8;
	bits[5] = t;
	t >>= 8;
	bits[4] = t;
	t = C->count[1];
	bits[3] = t;
	t >>= 8;
	bits[2] = t;
	t >>= 8;
	bits[1] = t;
	t >>= 8;
	bits[0] = t;

	/* Pad out to 56 mod 64. */
	index = (C->count[0] >> 3) & 0x3f;
	padLen = (index < 56) ? (56 - index) : ((64 + 56) - index);
	SHA256Update(C, padding, padLen);

	/* Append length (before padding) */
	SHA256Update(C, bits, sizeof (bits));

	/* Store state in digest */
	for (i = j = 0; i < 8; i++, j += 4) {
		t = C->state[i];
		digest[j + 3] = t;
		t >>= 8;
		digest[j + 2] = t;
		t >>= 8;
		digest[j + 1] = t;
		t >>= 8;
		digest[j] = t;
	}

	/* Zeroize sensitive information. */
	memset(C, 0, sizeof (sha256_ctx_t));
}

void
generate_hash(struct gr_pw_entry *entry)
{
	sha256_ctx_t context;
	char *pos;

	pos = memchr(entry->passwd, '\n', strlen((char *)entry->passwd));
	if (pos)
		*pos = '\0';

	SHA256Init(&context);
	SHA256Update(&context, entry->salt, GR_SALT_SIZE);
	SHA256Update(&context, entry->passwd, strlen((char *)entry->passwd));
	SHA256Final(&context, entry->sum);

	return;
}
