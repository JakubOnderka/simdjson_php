#ifndef SIMDJSON_VECTOR8_H
#define SIMDJSON_VECTOR8_H

#ifdef __SSE2__
#include <emmintrin.h>
typedef __m128i simdjson_vector8;
#endif

#if defined(__aarch64__) || defined(_M_ARM64)
#include <arm_neon.h>
typedef uint8x16_t simdjson_vector8;
#endif

static inline void simdjson_vector8_load(simdjson_vector8 *v, const uint8_t *s)
{
#ifdef __SSE2__
    *v = _mm_loadu_si128((const __m128i *) s);
#elif defined(__aarch64__) || defined(_M_ARM64)
    *v = vld1q_u8(s);
#endif
}

static inline void simdjson_vector8_store(uint8_t *s, simdjson_vector8 v)
{
#ifdef __SSE2__
    _mm_storeu_si128((simdjson_vector8*)s, v);
#elif defined(__aarch64__) || defined(_M_ARM64)
    vst1q_u8(s, v);
#endif
}

static inline simdjson_vector8 simdjson_vector8_ssub(const simdjson_vector8 v1, const simdjson_vector8 v2)
{
#ifdef __SSE2__
    return _mm_subs_epu8(v1, v2);
#elif defined(__aarch64__) || defined(_M_ARM64)
    return vqsubq_u8(v1, v2);
#endif
}

static inline simdjson_vector8 simdjson_vector8_broadcast(const uint8_t c)
{
#ifdef __SSE2__
    return _mm_set1_epi8(c);
#elif defined(__aarch64__) || defined(_M_ARM64)
    return vdupq_n_u8(c);
#endif
}

static inline simdjson_vector8 simdjson_vector8_eq(const simdjson_vector8 v1, const simdjson_vector8 v2)
{
#ifdef __SSE2__
    return _mm_cmpeq_epi8(v1, v2);
#elif defined(__aarch64__) || defined(_M_ARM64)
    return vceqq_u8(v1, v2);
#endif
}

static inline bool simdjson_vector8_non_zero(const simdjson_vector8 v)
{
#ifdef __SSE2__
    return _mm_movemask_epi8(v) != 0;
#elif defined(__aarch64__) || defined(_M_ARM64)
    return vmaxvq_u8(v) != 0;
#endif
}

static inline simdjson_vector8 simdjson_vector8_has_le(const simdjson_vector8 v1, const simdjson_vector8 v2)
{
#ifdef __SSE2__
      return _mm_cmpeq_epi8(_mm_max_epu8(v1, v2), v2);
#elif defined(__aarch64__) || defined(_M_ARM64)
    return vcleq_u8(v1, v2);
#endif
}

static inline simdjson_vector8 simdjson_vector8_or(const simdjson_vector8 v1, const simdjson_vector8 v2)
{
#ifdef __SSE2__
    return _mm_or_si128(v1, v2);
#elif defined(__aarch64__) || defined(_M_ARM64)
    return vorrq_u8(v1, v2);
#endif
}

/**
* Check if given vector contais char that needs to be escaped in JSON (control char, quote or backslash)
*/
static inline bool simdjson_vector8_need_escape(const simdjson_vector8 v)
{
    simdjson_vector8 has_control = simdjson_vector8_has_le(v, simdjson_vector8_broadcast(0x1F));
    simdjson_vector8 has_quote = simdjson_vector8_eq(v, simdjson_vector8_broadcast((unsigned char) '"'));
    simdjson_vector8 has_backslash = simdjson_vector8_eq(v, simdjson_vector8_broadcast((unsigned char) '\\'));

    simdjson_vector8 output = simdjson_vector8_or(has_control, has_quote);
    output = simdjson_vector8_or(output, has_backslash);
    return simdjson_vector8_non_zero(output);
}

#endif //SIMDJSON_VECTOR8_H
