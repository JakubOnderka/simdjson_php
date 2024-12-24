#ifndef SIMDJSON_VECTOR8_TARGET_AVX2_H
#define SIMDJSON_VECTOR8_TARGET_AVX2_H

#include <stdint.h>
#include <x86intrin.h>

#define TARGET_AVX2 __attribute__((target("avx2")))

#define simdjson_avx2_or _mm256_or_si256
#define simdjson_avx2_eq _mm256_cmpeq_epi8
#define simdjson_avx2_broadcast _mm256_set1_epi8
#define simdjson_avx2_has_le(_v1, _v2) _mm256_cmpeq_epi8(_mm256_max_epu8(_v1, _v2), _v2)
#define simdjson_avx2_to_bitmask(_v) _mm256_movemask_epi8(_v)

struct simdjson_avx2 {
    __m256i chunk;

    TARGET_AVX2 inline void load(const uint8_t *s) {
        chunk = _mm256_loadu_si256((const __m256i *) s);
    }

    TARGET_AVX2 inline void store(uint8_t *s) {
        _mm256_storeu_si256((__m256i*)s, chunk);
    }

    TARGET_AVX2 inline uint64_t needs_escaping() {
        auto has_control = simdjson_avx2_has_le(chunk, simdjson_avx2_broadcast(0x1F));
        auto has_quote = simdjson_avx2_eq(chunk, simdjson_avx2_broadcast((unsigned char) '"'));
        auto has_backslash = simdjson_avx2_eq(chunk, simdjson_avx2_broadcast((unsigned char) '\\'));

        auto output = simdjson_avx2_or(has_control, has_quote);
        output = simdjson_avx2_or(output, has_backslash);
        return simdjson_avx2_to_bitmask(output);
    }

    TARGET_AVX2 inline uint64_t escape_index(uint64_t mask) {
        return __builtin_ctzll(mask);
    }
};

#endif //SIMDJSON_VECTOR8_TARGET_AVX2_H
