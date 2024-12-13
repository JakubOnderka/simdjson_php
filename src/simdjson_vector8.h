#ifndef SIMDJSON_VECTOR8_H
#define SIMDJSON_VECTOR8_H

#ifdef __SSE2__
#include <emmintrin.h>
#endif
#if defined(__aarch64__) || defined(_M_ARM64)
#include <arm_neon.h>
#endif

typedef uint8x16_t simdjson_vector8;

static inline void simdjson_vector8_load(simdjson_vector8 *v, const uint8_t *s)
{
#ifdef __SSE2__
    *v = _mm_loadu_si128((const __m128i *) s);
#elif defined(__aarch64__) || defined(_M_ARM64)
    *v = vld1q_u8(s);
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

static inline bool simdjson_vector8_is_highbit_set(const simdjson_vector8 v)
{
#ifdef __SSE2__
    return _mm_movemask_epi8(v) != 0;
#elif defined(__aarch64__) || defined(_M_ARM64)
    return vmaxvq_u8(v) > 0x7F;
#endif
}

static inline bool simdjson_vector8_has(const simdjson_vector8 v, const uint8_t c)
{
    return simdjson_vector8_is_highbit_set(simdjson_vector8_eq(v, simdjson_vector8_broadcast(c)));
}

static inline bool simdjson_vector8_has_le(const simdjson_vector8 v, const uint8_t c)
{
    return simdjson_vector8_has(simdjson_vector8_ssub(v, simdjson_vector8_broadcast(c)), 0);
}

#endif //SIMDJSON_VECTOR8_H
