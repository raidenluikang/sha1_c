#include "sha1.h"

static void sha1_ctx_process(sha1_context_t* ctx);
static void set_word(uint32_t h, uint8_t * o)
{
	o[0] = h >> 24;
	o[1] = h >> 16;
	o[2] = h >> 8;
	o[3] = h >> 0;
}

/** size given in bytes */
static void sha1_ctx_inc_bits(sha1_context_t* ctx, size_t size)
{
	/* size * 8  --> need add to ctx->lo_bits + ctx->hi_bits*2^32 */

	ctx->hi_bits += size >> 29; /* 32 - 3 = 39*/
	size &= ( 1 << 29 ) - 1;
	size <<= 3; /* size * 8 */
	if (size > UINT32_MAX - ctx->lo_bits)
	{
		++(ctx->hi_bits);
	}
	ctx->lo_bits += size;
}

void sha1_ctx_init(sha1_context_t* ctx)
{
	ctx->index = 0;
	ctx->lo_bits = 0;
	ctx->hi_bits = 0;
	
	ctx->h0 = 0x67452301;
	ctx->h1 = 0xEFCDAB89;
	ctx->h2 = 0x98BADCFE;
	ctx->h3 = 0x10325476;
	ctx->h4 = 0xC3D2E1F0;
}

void sha1_ctx_finish(sha1_context_t* ctx)
{
	uint8_t* bytes = (uint8_t*)(ctx->w);
	
	bytes[ctx->index++] = 0x80;
	
	if (ctx->index > 56) {
		while (ctx->index < 64)
			bytes[ctx->index++] = 0x00;
		sha1_ctx_process(ctx);
		ctx->index = 0;
	}

	while (ctx->index < 56)
		bytes[ctx->index++] = 0x00;
	set_word(ctx->hi_bits, bytes + 56);
	set_word(ctx->lo_bits, bytes + 60);

	sha1_ctx_process(ctx);
}

void sha1_ctx_update(sha1_context_t* restrict ctx, void * restrict data, size_t size)
{
	
	uint8_t* bytes = (uint8_t*)(ctx->w);
	
	uint8_t* d = data;
	
	sha1_ctx_inc_bits(ctx, size);
	
	if (ctx->index + size >= 64) {
		if (ctx->index > 0) {
			size_t diff = 64 - ctx->index;
			for (size_t i = 0; i != diff; ++i) {
				bytes[ctx->index++] = *d++;
			}
			size -= diff;
			sha1_ctx_process(ctx);
		}

		ctx->index = 0;
		
		size_t number = size >> 6; /* size / 64  */
		for (size_t i = 0; i != number; ++i) 
		{
			bytes[0] = d[0];
			bytes[1] = d[1];
			bytes[2] = d[2];
			bytes[3] = d[3];
			bytes[4] = d[4];
			bytes[5] = d[5];
			bytes[6] = d[6];
			bytes[7] = d[7];

			bytes[8] = d[8];
			bytes[9] = d[9];
			bytes[10] = d[10];
			bytes[11] = d[11];
			bytes[12] = d[12];
			bytes[13] = d[13];
			bytes[14] = d[14];
			bytes[15] = d[15];

			bytes[16] = d[16];
			bytes[17] = d[17];
			bytes[18] = d[18];
			bytes[19] = d[19];
			bytes[20] = d[20];
			bytes[21] = d[21];
			bytes[22] = d[22];
			bytes[23] = d[23];

			bytes[24] = d[24];
			bytes[25] = d[25];
			bytes[26] = d[26];
			bytes[27] = d[27];
			bytes[28] = d[28];
			bytes[29] = d[29];
			bytes[30] = d[30];
			bytes[31] = d[31];

			bytes[32] = d[32];
			bytes[33] = d[33];
			bytes[34] = d[34];
			bytes[35] = d[35];
			bytes[36] = d[36];
			bytes[37] = d[37];
			bytes[38] = d[38];
			bytes[39] = d[39];

			bytes[40] = d[40];
			bytes[41] = d[41];
			bytes[42] = d[42];
			bytes[43] = d[43];
			bytes[44] = d[44];
			bytes[45] = d[45];
			bytes[46] = d[46];
			bytes[47] = d[47];

			bytes[48] = d[48];
			bytes[49] = d[49];
			bytes[50] = d[50];
			bytes[51] = d[51];
			bytes[52] = d[52];
			bytes[53] = d[53];
			bytes[54] = d[54];
			bytes[55] = d[55];

			bytes[56] = d[56];
			bytes[57] = d[57];
			bytes[58] = d[58];
			bytes[59] = d[59];
			bytes[60] = d[60];
			bytes[61] = d[61];
			bytes[62] = d[62];
			bytes[63] = d[63];

			sha1_ctx_process(ctx);

			d += 64;
		}

		size &= 63;
	}

	while (size > 0) {
		bytes[ctx->index++] = *d++;
		--size;
	}
}

static uint32_t rol_1(uint32_t value) 
{
	return (value << 1) | (value >> (32 - 1));
}
static uint32_t rol_5(uint32_t value)
{
	return (value << 5) | (value >> (32 - 5));
}
static uint32_t rol_30(uint32_t value)
{
	return (value << 30) | (value >> (32 - 30));
}


size_t sha1_ctx_result(sha1_context_t* restrict ctx, uint8_t* restrict out)
{
	set_word(ctx->h0, out + 0);
	set_word(ctx->h1, out + 4);
	set_word(ctx->h2, out + 8);
	set_word(ctx->h3, out + 12);
	set_word(ctx->h4, out + 16);
	return 20;
}

static uint32_t sha1_swap32(uint32_t w)
{
	w = ((w << 8) & 0xFF00FF00) | ((w >> 8) & 0xFF00FF);
	return (w << 16) | (w >> 16);
}

static void sha1_ctx_process(sha1_context_t* ctx)
{
	uint32_t a = ctx->h0, b = ctx->h1, c = ctx->h2, d = ctx->h3, e = ctx->h4;

#if __BYTE_ORDER == __LITTLE_ENDIAN
	{
		ctx->w[0] = sha1_swap32(ctx->w[0]);
		ctx->w[1] = sha1_swap32(ctx->w[1]);
		ctx->w[2] = sha1_swap32(ctx->w[2]);
		ctx->w[3] = sha1_swap32(ctx->w[3]);

		ctx->w[4] = sha1_swap32(ctx->w[4]);
		ctx->w[5] = sha1_swap32(ctx->w[5]);
		ctx->w[6] = sha1_swap32(ctx->w[6]);
		ctx->w[7] = sha1_swap32(ctx->w[7]);

		ctx->w[8] = sha1_swap32(ctx->w[8]);
		ctx->w[9] = sha1_swap32(ctx->w[9]);
		ctx->w[10] = sha1_swap32(ctx->w[10]);
		ctx->w[11] = sha1_swap32(ctx->w[11]);

		ctx->w[12] = sha1_swap32(ctx->w[12]);
		ctx->w[13] = sha1_swap32(ctx->w[13]);
		ctx->w[14] = sha1_swap32(ctx->w[14]);
		ctx->w[15] = sha1_swap32(ctx->w[15]);
	}
#endif 
	
#define fx(b,c,d)  ((b & c) | ((~b) & d))
#define fy(b,c,d)  (b ^ c ^ d)
#define fz(b,c,d)  ((b & c) |(b & d) | (c & d))

#define R_UPD(s) ctx->w[s] = rol_1(ctx->w[(s + 13 ) & 15 ] ^ ctx->w[ (s + 8) & 15] ^ ctx->w[( s + 2) & 15] ^ ctx->w[s]);
#define R0(a,b,c,d,e, s, func, key) e = rol_5(a) + func(b,c,d) + e + ctx->w[s] + key; b = rol_30(b);
#define R1(a,b,c,d,e, s, func, key)  R_UPD(s) R0(a,b,c,d,e,s,func,key)

	R0(a, b, c, d, e, 0, fx, 0x5A827999)
	R0(e, a, b, c, d, 1, fx, 0x5A827999)
	R0(d, e, a, b, c, 2, fx, 0x5A827999)
	R0(c, d, e, a, b, 3, fx, 0x5A827999)
	R0(b, c, d, e, a, 4, fx, 0x5A827999)

	R0(a, b, c, d, e, 5, fx, 0x5A827999)
	R0(e, a, b, c, d, 6, fx, 0x5A827999)
	R0(d, e, a, b, c, 7, fx, 0x5A827999)
	R0(c, d, e, a, b, 8, fx, 0x5A827999)
	R0(b, c, d, e, a, 9, fx, 0x5A827999)

	R0(a, b, c, d, e, 10, fx, 0x5A827999)
	R0(e, a, b, c, d, 11, fx, 0x5A827999)
	R0(d, e, a, b, c, 12, fx, 0x5A827999)
	R0(c, d, e, a, b, 13, fx, 0x5A827999)
	R0(b, c, d, e, a, 14, fx, 0x5A827999)


	R0(a, b, c, d, e, 15, fx, 0x5A827999)
	R1(e, a, b, c, d, 0, fx, 0x5A827999)
	R1(d, e, a, b, c, 1, fx, 0x5A827999)
	R1(c, d, e, a, b, 2, fx, 0x5A827999)
	R1(b, c, d, e, a, 3, fx, 0x5A827999)

	/// t >= 20 .. 39
	R1(a, b, c, d, e, 4, fy, 0x6ED9EBA1)
	R1(e, a, b, c, d, 5, fy, 0x6ED9EBA1)
	R1(d, e, a, b, c, 6, fy, 0x6ED9EBA1)
	R1(c, d, e, a, b, 7, fy, 0x6ED9EBA1)
	R1(b, c, d, e, a, 8, fy, 0x6ED9EBA1)

	R1(a, b, c, d, e, 9, fy, 0x6ED9EBA1)
	R1(e, a, b, c, d, 10, fy, 0x6ED9EBA1)
	R1(d, e, a, b, c, 11, fy, 0x6ED9EBA1)
	R1(c, d, e, a, b, 12, fy, 0x6ED9EBA1)
	R1(b, c, d, e, a, 13, fy, 0x6ED9EBA1)

	R1(a, b, c, d, e, 14, fy, 0x6ED9EBA1)
	R1(e, a, b, c, d, 15, fy, 0x6ED9EBA1)
	R1(d, e, a, b, c, 0, fy, 0x6ED9EBA1)
	R1(c, d, e, a, b, 1, fy, 0x6ED9EBA1)
	R1(b, c, d, e, a, 2, fy, 0x6ED9EBA1)


	R1(a, b, c, d, e, 3, fy, 0x6ED9EBA1)
	R1(e, a, b, c, d, 4, fy, 0x6ED9EBA1)
	R1(d, e, a, b, c, 5, fy, 0x6ED9EBA1)
	R1(c, d, e, a, b, 6, fy, 0x6ED9EBA1)
	R1(b, c, d, e, a, 7, fy, 0x6ED9EBA1)

	// t >= 40 .. 59
	R1(a, b, c, d, e, 8, fz, 0x8F1BBCDC)
	R1(e, a, b, c, d, 9, fz, 0x8F1BBCDC)
	R1(d, e, a, b, c, 10, fz, 0x8F1BBCDC)
	R1(c, d, e, a, b, 11, fz, 0x8F1BBCDC)
	R1(b, c, d, e, a, 12, fz, 0x8F1BBCDC)

	R1(a, b, c, d, e, 13, fz, 0x8F1BBCDC)
	R1(e, a, b, c, d, 14, fz, 0x8F1BBCDC)
	R1(d, e, a, b, c, 15, fz, 0x8F1BBCDC)
	R1(c, d, e, a, b, 0, fz, 0x8F1BBCDC)
	R1(b, c, d, e, a, 1, fz, 0x8F1BBCDC)

	R1(a, b, c, d, e, 2, fz, 0x8F1BBCDC)
	R1(e, a, b, c, d, 3, fz, 0x8F1BBCDC)
	R1(d, e, a, b, c, 4, fz, 0x8F1BBCDC)
	R1(c, d, e, a, b, 5, fz, 0x8F1BBCDC)
	R1(b, c, d, e, a, 6, fz, 0x8F1BBCDC)


	R1(a, b, c, d, e, 7, fz, 0x8F1BBCDC)
	R1(e, a, b, c, d, 8, fz, 0x8F1BBCDC)
	R1(d, e, a, b, c, 9, fz, 0x8F1BBCDC)
	R1(c, d, e, a, b, 10, fz, 0x8F1BBCDC)
	R1(b, c, d, e, a, 11, fz, 0x8F1BBCDC)

	// t >= 60 .. 79
	R1(a, b, c, d, e, 12, fy, 0xCA62C1D6)
	R1(e, a, b, c, d, 13, fy, 0xCA62C1D6)
	R1(d, e, a, b, c, 14, fy, 0xCA62C1D6)
	R1(c, d, e, a, b, 15, fy, 0xCA62C1D6)
	R1(b, c, d, e, a, 0, fy, 0xCA62C1D6)

	R1(a, b, c, d, e, 1, fy, 0xCA62C1D6)
	R1(e, a, b, c, d, 2, fy, 0xCA62C1D6)
	R1(d, e, a, b, c, 3, fy, 0xCA62C1D6)
	R1(c, d, e, a, b, 4, fy, 0xCA62C1D6)
	R1(b, c, d, e, a, 5, fy, 0xCA62C1D6)

	R1(a, b, c, d, e, 6, fy, 0xCA62C1D6)
	R1(e, a, b, c, d, 7, fy, 0xCA62C1D6)
	R1(d, e, a, b, c, 8, fy, 0xCA62C1D6)
	R1(c, d, e, a, b, 9, fy, 0xCA62C1D6)
	R1(b, c, d, e, a, 10, fy, 0xCA62C1D6)


	R1(a, b, c, d, e, 11, fy, 0xCA62C1D6)
	R1(e, a, b, c, d, 12, fy, 0xCA62C1D6)
	R1(d, e, a, b, c, 13, fy, 0xCA62C1D6)
	R1(c, d, e, a, b, 14, fy, 0xCA62C1D6)
	R1(b, c, d, e, a, 15, fy, 0xCA62C1D6)

#undef fx
#undef fy
#undef fz
#undef R0
#undef R1


	ctx->h0 += a, ctx->h1 += b, ctx->h2 += c, ctx->h3 += d, ctx->h4 += e;
}