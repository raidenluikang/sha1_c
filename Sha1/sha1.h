#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef _MSC_VER
#define restrict __restrict
#endif 

typedef struct sha1_context_s sha1_context_t;

struct sha1_context_s
{
	uint32_t w[16];
	uint32_t h0, h1, h2, h3, h4;
	uint32_t lo_bits, hi_bits;
	uint32_t index;
};

void sha1_ctx_init(sha1_context_t* ctx);
void sha1_ctx_finish(sha1_context_t* ctx);
void sha1_ctx_update(sha1_context_t* restrict ctx, void * restrict data, size_t size);
size_t sha1_ctx_result(sha1_context_t* restrict ctx, uint8_t* restrict  out);
