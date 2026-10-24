#ifndef SIMDJSON_VECTOR8_TARGET_AVX512_H
#define SIMDJSON_VECTOR8_TARGET_AVX512_H

#include <stdint.h>
#include <immintrin.h>

#define SIMDJSON_TARGET_AVX512 __attribute__((target("avx512bw")))
#define SIMDJSON_AVX512_SIZE sizeof(__m512i)

#define simdjson_avx512_or(_v1, _v2) ((_v1) | (_v2))
#define simdjson_avx512_eq _mm512_cmpeq_epi8_mask
#define simdjson_avx512_broadcast _mm512_set1_epi8
#define simdjson_avx512_has_le(_v1, _v2) _mm512_cmple_epu8_mask((_v1), (_v2))
#define simdjson_avx512_to_bitmask(_v) (_v)

struct simdjson_avx512 {
    __m512i chunk;

    SIMDJSON_TARGET_AVX512 inline void load(const uint8_t *s) {
        chunk = _mm512_loadu_si512((const void *) s);
    }

    SIMDJSON_TARGET_AVX512 inline void store(uint8_t *s) {
        _mm512_storeu_si512((void *) s, chunk);
    }

    SIMDJSON_TARGET_AVX512 inline uint64_t needs_escaping() {
        auto has_control = simdjson_avx512_has_le(chunk, simdjson_avx512_broadcast(0x1F));
        auto has_quote = simdjson_avx512_eq(chunk, simdjson_avx512_broadcast((unsigned char) '"'));
        auto has_backslash = simdjson_avx512_eq(chunk, simdjson_avx512_broadcast((unsigned char) '\\'));

        auto output = simdjson_avx512_or(has_control, has_quote);
        output = simdjson_avx512_or(output, has_backslash);
        return simdjson_avx512_to_bitmask(output);
    }

    SIMDJSON_TARGET_AVX512 inline uint64_t escape_index(uint64_t mask) {
        return __builtin_ctzll(mask);
    }
};

#endif //SIMDJSON_VECTOR8_TARGET_AVX512_H
