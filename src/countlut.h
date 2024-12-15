#ifndef COUNTLUT_H
#define COUNTLUT_H

#include <stdint.h>

unsigned simdjson_u64toa_countlut(uint64_t value, char* buffer);
unsigned simdjson_i64toa_countlut(int64_t value, char* buffer);

#endif //COUNTLUT_H
