#ifndef SIMDJSON_INTEGER_WRITER_H
#define SIMDJSON_INTEGER_WRITER_H

#include <cstring>
#include "Zend/zend_portability.h"

static const char decimal_table[200] = {
    0x30, 0x30, 0x30, 0x31, 0x30, 0x32, 0x30, 0x33, 0x30, 0x34, 0x30, 0x35,
    0x30, 0x36, 0x30, 0x37, 0x30, 0x38, 0x30, 0x39, 0x31, 0x30, 0x31, 0x31,
    0x31, 0x32, 0x31, 0x33, 0x31, 0x34, 0x31, 0x35, 0x31, 0x36, 0x31, 0x37,
    0x31, 0x38, 0x31, 0x39, 0x32, 0x30, 0x32, 0x31, 0x32, 0x32, 0x32, 0x33,
    0x32, 0x34, 0x32, 0x35, 0x32, 0x36, 0x32, 0x37, 0x32, 0x38, 0x32, 0x39,
    0x33, 0x30, 0x33, 0x31, 0x33, 0x32, 0x33, 0x33, 0x33, 0x34, 0x33, 0x35,
    0x33, 0x36, 0x33, 0x37, 0x33, 0x38, 0x33, 0x39, 0x34, 0x30, 0x34, 0x31,
    0x34, 0x32, 0x34, 0x33, 0x34, 0x34, 0x34, 0x35, 0x34, 0x36, 0x34, 0x37,
    0x34, 0x38, 0x34, 0x39, 0x35, 0x30, 0x35, 0x31, 0x35, 0x32, 0x35, 0x33,
    0x35, 0x34, 0x35, 0x35, 0x35, 0x36, 0x35, 0x37, 0x35, 0x38, 0x35, 0x39,
    0x36, 0x30, 0x36, 0x31, 0x36, 0x32, 0x36, 0x33, 0x36, 0x34, 0x36, 0x35,
    0x36, 0x36, 0x36, 0x37, 0x36, 0x38, 0x36, 0x39, 0x37, 0x30, 0x37, 0x31,
    0x37, 0x32, 0x37, 0x33, 0x37, 0x34, 0x37, 0x35, 0x37, 0x36, 0x37, 0x37,
    0x37, 0x38, 0x37, 0x39, 0x38, 0x30, 0x38, 0x31, 0x38, 0x32, 0x38, 0x33,
    0x38, 0x34, 0x38, 0x35, 0x38, 0x36, 0x38, 0x37, 0x38, 0x38, 0x38, 0x39,
    0x39, 0x30, 0x39, 0x31, 0x39, 0x32, 0x39, 0x33, 0x39, 0x34, 0x39, 0x35,
    0x39, 0x36, 0x39, 0x37, 0x39, 0x38, 0x39, 0x39,
};

// Forward unsigned-int writer (cascade-on-magnitude, no upfront digit_count).
// Built from a non-recursive DAG of always_inline helpers — gcc and MSVC
// refuse to inline recursive `always_inline`/`__forceinline` functions.
// Caller must guarantee at least 20 bytes available at p. All helpers
// return pointer past the last digit written.

// Caller guarantees v < 100. Writes 1-2 digits.
zend_always_inline static char* write_lt100(char* p, uint64_t v) {
  if (v < 10) { *p++ = char('0' + v); return p; }
  memcpy(p, &decimal_table[v * 2], 2);
  return p + 2;
}

// Caller guarantees v < 10000. Writes 1-4 digits.
zend_always_inline static char* write_lt10000(char* p, uint64_t v) {
  if (v < 100) return write_lt100(p, v);
  uint64_t hi = v / 100, lo = v % 100;
  if (v < 1000) {
    *p++ = char('0' + hi);
  } else {
    memcpy(p, &decimal_table[hi * 2], 2);
    p += 2;
  }
  memcpy(p, &decimal_table[lo * 2], 2);
  return p + 2;
}

// Caller guarantees v < 10000. Always writes exactly 4 digits.
zend_always_inline static void write_4_digits(char* p, uint64_t v) {
  uint64_t hi = v / 100, lo = v % 100;
  memcpy(p,     &decimal_table[hi * 2], 2);
  memcpy(p + 2, &decimal_table[lo * 2], 2);
}

// Caller guarantees v < 10^8. Writes 1-8 digits.
zend_always_inline static char* write_lt1e8(char* p, uint64_t v) {
  if (v < 10000) return write_lt10000(p, v);
  uint64_t hi = v / 10000, lo = v % 10000;
  p = write_lt10000(p, hi);
  write_4_digits(p, lo);
  return p + 4;
}

zend_always_inline char* simdjson_write_uint_jeaiii(char* p, uint64_t v) {
  if (v < 10000ULL) return write_lt10000(p, v);
  if (v < 100000000ULL) {                   // 5-8 digits
    uint64_t hi = v / 10000, lo = v % 10000;
    p = write_lt10000(p, hi);
    write_4_digits(p, lo);
    return p + 4;
  }
  if (v < 10000000000000000ULL) {           // 9-16 digits
    uint64_t hi = v / 100000000ULL, lo = v % 100000000ULL;
    p = write_lt1e8(p, hi);
    uint64_t lo_hi = lo / 10000, lo_lo = lo % 10000;
    write_4_digits(p,     lo_hi);
    write_4_digits(p + 4, lo_lo);
    return p + 8;
  }
  // 17-20 digits
  uint64_t hi = v / 10000000000000000ULL, lo = v % 10000000000000000ULL;
  p = write_lt10000(p, hi);
  uint64_t lo_a = lo / 100000000ULL, lo_b = lo % 100000000ULL;
  uint64_t lo_a_hi = lo_a / 10000, lo_a_lo = lo_a % 10000;
  uint64_t lo_b_hi = lo_b / 10000, lo_b_lo = lo_b % 10000;
  write_4_digits(p,      lo_a_hi);
  write_4_digits(p + 4,  lo_a_lo);
  write_4_digits(p + 8,  lo_b_hi);
  write_4_digits(p + 12, lo_b_lo);
  return p + 16;
}

zend_always_inline char* simdjson_write_int_jeaiii(char* p, int64_t v) {
    bool negative = v < 0;
    uint64_t pv = negative
        ? 0 - static_cast<uint64_t>(v)
        : static_cast<uint64_t>(v);
    *p = '-';
    p += negative;
    return simdjson_write_uint_jeaiii(p, pv);
}

#endif //SIMDJSON_INTEGER_WRITER_H
