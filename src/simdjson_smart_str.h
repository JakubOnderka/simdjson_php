#ifndef SIMDJSON_SMART_STR_H
#define SIMDJSON_SMART_STR_H

#include "php.h"
#include "zend_smart_str.h"

// Copied from zend_smart_str.c
#define SMART_STR_OVERHEAD   (ZEND_MM_OVERHEAD + _ZSTR_HEADER_SIZE + 1)
#define SMART_STR_START_SIZE 256
#define SMART_STR_START_LEN  (SMART_STR_START_SIZE - SMART_STR_OVERHEAD)
#define SMART_STR_PAGE       4096
#define SMART_STR_NEW_LEN(len) \
	(ZEND_MM_ALIGNED_SIZE_EX(len + SMART_STR_OVERHEAD, SMART_STR_PAGE) - SMART_STR_OVERHEAD)

static void simdjson_smart_str_init(smart_str *str) {
    ZEND_ASSERT(str->s == NULL);
    str->a = SMART_STR_START_LEN;
    str->s = zend_string_alloc(str->a, 0);
    ZSTR_LEN(str->s) = 0;
}

static void simdjson_smart_str_erealloc(smart_str *str, size_t len) {
    ZEND_ASSERT(str->s != NULL);
    str->a = SMART_STR_NEW_LEN(len);
    str->s = (zend_string *) erealloc2(str->s, str->a + _ZSTR_HEADER_SIZE + 1, _ZSTR_HEADER_SIZE + ZSTR_LEN(str->s));
}

static zend_always_inline char* simdjson_smart_str_alloc(smart_str *str, size_t len) {
    ZEND_ASSERT(str->s != NULL);
    len += ZSTR_LEN(str->s);
    if (UNEXPECTED(len >= str->a)) {
        simdjson_smart_str_erealloc(str, len);
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
    if (free_space > SMART_STR_PAGE) { // reallocate just when saving is bigger than 4096 bytes
        ZEND_ASSERT(!ZSTR_IS_INTERNED(str->s));
        ZEND_ASSERT(GC_REFCOUNT(str->s) == 1);
        return zend_string_realloc(str->s, ZSTR_LEN(str->s), 0);
    }
    return str->s;
}

#endif //SIMDJSON_SMART_STR_H
