#ifndef SIMDJSON_VECTOR8_TARGET_AVX256_H
#define SIMDJSON_VECTOR8_TARGET_AVX256_H

#include <stdint.h>
#include <x86intrin.h>

#define TARGET_AVX2 __attribute__((target("avx2")))

typedef __m256i simdjson_avx2;

TARGET_AVX2 static inline simdjson_avx2 simdjson_avx2_load(const uint8_t *s) {
    return _mm256_loadu_si256((const simdjson_avx2 *) s);
}

TARGET_AVX2 static inline void simdjson_avx2_store(uint8_t *s, simdjson_avx2 v) {
    _mm256_storeu_si256((simdjson_avx2*)s, v);
}

TARGET_AVX2 static inline simdjson_avx2 simdjson_avx2_broadcast(const uint8_t c) {
    return _mm256_set1_epi8(c);
}

TARGET_AVX2 static inline simdjson_avx2 simdjson_avx2_eq(const simdjson_avx2 v1, const simdjson_avx2 v2) {
    return _mm256_cmpeq_epi8(v1, v2);
}

TARGET_AVX2 static inline bool simdjson_avx2_non_zero(const simdjson_avx2 v) {
    return _mm256_movemask_epi8(v) != 0;
}

TARGET_AVX2 static inline simdjson_avx2 simdjson_avx2_has_le(const simdjson_avx2 v1, const simdjson_avx2 v2) {
    return _mm256_cmpeq_epi8(_mm256_max_epu8(v1, v2), v2);
}

TARGET_AVX2 static inline simdjson_avx2 simdjson_avx2_or(const simdjson_avx2 v1, const simdjson_avx2 v2) {
    return _mm256_or_si256(v1, v2);
}

/**
* Check if given vector contais char that needs to be escaped in JSON (control char, quote or backslash)
*/
TARGET_AVX2 static inline bool simdjson_avx2_need_escape(const simdjson_avx2 v) {
    simdjson_avx2 has_control = simdjson_avx2_has_le(v, simdjson_avx2_broadcast(0x1F));
    simdjson_avx2 has_quote = simdjson_avx2_eq(v, simdjson_avx2_broadcast((unsigned char) '"'));
    simdjson_avx2 has_backslash = simdjson_avx2_eq(v, simdjson_avx2_broadcast((unsigned char) '\\'));

    simdjson_avx2 output = simdjson_avx2_or(has_control, has_quote);
    output = simdjson_avx2_or(output, has_backslash);
    return simdjson_avx2_non_zero(output);
}

#endif //SIMDJSON_VECTOR8_TARGET_AVX256_H
