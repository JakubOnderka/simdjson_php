#ifndef SIMDJSON_SMART_STR_H
#define SIMDJSON_SMART_STR_H

#include "php.h"
#include "zend_smart_str.h"

static zend_always_inline size_t simdjson_smart_str_alloc(smart_str *str, size_t len) {
    ZEND_ASSERT(str->s != NULL);
    len += ZSTR_LEN(str->s);
    if (UNEXPECTED(len >= str->a)) {
        smart_str_erealloc(str, len);
    }
    return len;
}

static zend_always_inline char* simdjson_smart_str_extend(smart_str *dest, size_t len) {
    size_t new_len = simdjson_smart_str_alloc(dest, len);
    char *ret = ZSTR_VAL(dest->s) + ZSTR_LEN(dest->s);
    ZSTR_LEN(dest->s) = new_len;
    return ret;
}

static zend_always_inline void simdjson_smart_str_appendc_unsafe(smart_str *dest, char ch) {
    ZSTR_VAL(dest->s)[ZSTR_LEN(dest->s)++] = ch;
}

static zend_always_inline void simdjson_smart_str_appendc(smart_str *dest, char ch) {
    simdjson_smart_str_alloc(dest, 1);
    simdjson_smart_str_appendc_unsafe(dest, ch);
}

static zend_always_inline void simdjson_smart_str_appendl_unsafe(smart_str *dest, const char* str, size_t len) {
    memcpy(ZSTR_VAL(dest->s) + ZSTR_LEN(dest->s), str, len);
    ZSTR_LEN(dest->s) += len;
}

static zend_always_inline void simdjson_smart_str_appendl(smart_str *dest, const char *str, size_t len) {
    simdjson_smart_str_alloc(dest, len);
    simdjson_smart_str_appendl_unsafe(dest, str, len);
}

#endif //SIMDJSON_SMART_STR_H
