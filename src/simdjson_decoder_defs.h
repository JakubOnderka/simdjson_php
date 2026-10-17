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

// Opaque state backing SimdJsonDecodeIterator / simdjson_decode_iterate().
// Lazily parses a string containing one or more concatenated JSON documents,
// using simdjson's ondemand parser::iterate_many() API, one document at a time.
struct simdjson_decode_iterator_state;

/**
 * Creates the state for simdjson_decode_iterate().
 *
 * On success, returns a non-NULL state (the caller must eventually free it with
 * simdjson_decode_iterator_free()) and sets *error to 0.
 * On failure, returns NULL and sets *error to the simdjson error code.
 */
simdjson_decode_iterator_state *simdjson_decode_iterator_create(const zend_string *json, bool associative, size_t depth, size_t batch_size, simdjson_php_error_code *error);

/** Releases all resources owned by state. state may be NULL. */
void simdjson_decode_iterator_free(simdjson_decode_iterator_state *state);

/**
 * Advances the iterator to the next document and decodes it into *return_value.
 *
 * Returns true if a document was decoded into *return_value (the iterator's current index was
 * incremented).
 * Returns false if the stream is exhausted (in which case *error is left at 0) or if an
 * unrecoverable parse/decode error occurred (in which case *error is set to a non-zero simdjson
 * error code). Once this returns false, the iterator is considered finished.
 */
bool simdjson_decode_iterator_advance(simdjson_decode_iterator_state *state, zval *return_value, simdjson_php_error_code *error);

/**
 * Returns the 0-based index of the document last successfully produced by
 * simdjson_decode_iterator_advance(), or -1 if no document has been produced yet.
 */
zend_long simdjson_decode_iterator_current_index(const simdjson_decode_iterator_state *state);

#endif
