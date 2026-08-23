/*
  +----------------------------------------------------------------------+
  | simdjson_php                                                         |
  +----------------------------------------------------------------------+
  | This source file is subject to version 2.0 of the Apache license,    |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.apache.org/licenses/LICENSE-2.0.html                      |
  +----------------------------------------------------------------------+
  | Author: Tyson Andre <tandre@php.net>                                 |
  +----------------------------------------------------------------------+
*/
#ifndef SIMDJSON_PHP_BINDINGS_IMPL_H
#define SIMDJSON_PHP_BINDINGS_IMPL_H

#include "php.h"
#include "simdjson.h"

#if PHP_VERSION_ID >= 80600
// Since PHP 8.6, HT_SIZE_* macros was converted to functions, so we have to compute array size
#define SIMDJSON_DEDUP_DATA_SIZE(nTableSize) \
    ((size_t)nTableSize) * sizeof(Bucket) + ((size_t)(-((uint32_t)(-(nTableSize + nTableSize))))) * sizeof(uint32_t)
#else
#define SIMDJSON_DEDUP_DATA_SIZE(nTableSize) \
    HT_SIZE_EX(nTableSize, HT_SIZE_TO_MASK(nTableSize))
#endif

bool simdjson_realloc_needed(const zend_string *str);
bool simdjson_simple_decode(const char *json, size_t len, zval *return_value, bool associative);

// NOTE: Namespaces are C++ only functionality.
// To expose this functionality to other C PECLs,
// bindings.h exposes a forward class declaration of a class that only wraps simdjson::dom::parser
struct simdjson_php_parser {
public:
    simdjson::dom::parser parser;
    simdjson::ondemand::parser ondemand_parser;
    HashTable dedup_key_strings;
#if PHP_VERSION_ID >= 80200
    char dedup_key_strings_data[SIMDJSON_DEDUP_DATA_SIZE(SIMDJSON_DEDUP_STRING_COUNT)];
#endif
};

#endif
