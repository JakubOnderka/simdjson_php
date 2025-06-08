#ifndef SIMDJSON_VECTOR8_H
#define SIMDJSON_VECTOR8_H

// SSE2
#ifdef __SSE2__
#include <emmintrin.h>

#define simdjson_vector8_broadcast _mm_set1_epi8
#define simdjson_vector8_eq _mm_cmpeq_epi8
#define simdjson_vector8_or _mm_or_si128
#define simdjson_vector8_has_le(_v1, _v2) _mm_cmpeq_epi8(_mm_max_epu8(_v1, _v2), _v2)
#define simdjson_vector8_to_bitmask(_v) _mm_movemask_epi8(_v)
#endif

// NEON
#if defined(__aarch64__) || defined(_M_ARM64)
#include <arm_neon.h>

#define simdjson_vector8_broadcast vdupq_n_u8
#define simdjson_vector8_eq vceqq_u8
#define simdjson_vector8_or vorrq_u8
#define simdjson_vector8_has_le vcleq_u8
#define simdjson_vector8_to_bitmask(_v) vget_lane_u64(vreinterpret_u64_u8(vshrn_n_u16(vreinterpretq_u16_u8(_v), 4)), 0)
#endif

static zend_always_inline int _trailing_zeroes(uint64_t input_num) {
#ifdef _MSC_VER
    unsigned long ret;
    // Search the mask data from least significant bit (LSB)
    // to the most significant bit (MSB) for a set bit (1).
    _BitScanForward64(&ret, input_num);
    return (int)ret;
#else  // _MSC_VER
    return __builtin_ctzll(input_num);
#endif // _MSC_VER
}

struct simdjson_vector8 {
#ifdef __SSE2__
    __m128i chunk;
#elif defined(__aarch64__) || defined(_M_ARM64)
    uint8x16_t chunk;
#endif

    inline void load(const uint8_t *s) {
#ifdef __SSE2__
        chunk = _mm_loadu_si128((const __m128i *) s);
#elif defined(__aarch64__) || defined(_M_ARM64)
        chunk = vld1q_u8(s);
#endif
    }

    inline void store(uint8_t *s) {
#ifdef __SSE2__
        _mm_storeu_si128((__m128i*)s, chunk);
#elif defined(__aarch64__) || defined(_M_ARM64)
        vst1q_u8(s, chunk);
#endif
    }

    inline uint64_t needs_escaping() {
        auto has_control = simdjson_vector8_has_le(chunk, simdjson_vector8_broadcast(0x1F));
        auto has_quote = simdjson_vector8_eq(chunk, simdjson_vector8_broadcast((unsigned char) '"'));
        auto has_backslash = simdjson_vector8_eq(chunk, simdjson_vector8_broadcast((unsigned char) '\\'));

        auto output = simdjson_vector8_or(has_control, has_quote);
        output = simdjson_vector8_or(output, has_backslash);
        return simdjson_vector8_to_bitmask(output);
    }

    inline uint64_t escape_index(uint64_t mask) {
#ifdef __SSE2__
        return _trailing_zeroes(mask);
#elif defined(__aarch64__) || defined(_M_ARM64)
        return _trailing_zeroes(mask) / 4;
#endif
    }
};

#endif //SIMDJSON_VECTOR8_H
