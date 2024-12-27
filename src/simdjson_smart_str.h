#ifndef SIMDJSON_SMART_STR_H
#define SIMDJSON_SMART_STR_H

#include "php.h"
#include "zend_smart_str.h"

static zend_always_inline char* simdjson_smart_str_alloc(smart_str *str, size_t len) {
    ZEND_ASSERT(str->s != NULL);
    len += ZSTR_LEN(str->s);
    if (UNEXPECTED(len >= str->a)) {
        smart_str_erealloc(str, len);
    }
    return ZSTR_VAL(str->s) + ZSTR_LEN(str->s);
}

static zend_always_inline char* simdjson_smart_str_extend(smart_str *dest, size_t len) {
    char *ret = simdjson_smart_str_alloc(dest, len);
    ZSTR_LEN(dest->s) += len;
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

static zend_always_inline zend_string *simdjson_smart_str_extract(const smart_str *str) {
    ZSTR_VAL(str->s)[ZSTR_LEN(str->s)] = '\0';
    size_t free_space = str->a - ZSTR_LEN(str->s);
    if (free_space > 1024) { // reallocate just when saving is bigger than 1024 bytes
        return zend_string_realloc(str->s, ZSTR_LEN(str->s), 0);
    }
    return str->s;
}

#endif //SIMDJSON_SMART_STR_H
