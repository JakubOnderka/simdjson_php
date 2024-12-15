#ifndef SIMDJSON_COMPATIBILITY_H
#define SIMDJSON_COMPATIBILITY_H

/** Keep compatibility with older PHP version that do not support some macros */

#include "php.h"

// ZSTR_IS_VALID_UTF8 is available since PHP 8.3
#ifndef ZSTR_IS_VALID_UTF8
#define ZSTR_IS_VALID_UTF8(s) (GC_FLAGS(s) & IS_STR_VALID_UTF8)
#endif

// ZEND_HASH_PACKED_FOREACH_VAL is available since PHP 8.2
#ifndef ZEND_HASH_PACKED_FOREACH_VAL
#define	ZEND_HASH_PACKED_FOREACH_VAL(table, data) ZEND_HASH_FOREACH_VAL(table, data)
#endif

#ifndef ZEND_FALLTHROUGH
/* pseudo fallthrough keyword; */
#if defined(__GNUC__) && __GNUC__ >= 7
# define ZEND_FALLTHROUGH __attribute__((__fallthrough__))
#else
# define ZEND_FALLTHROUGH ((void)0)
#endif
#endif // #ifndef ZEND_FALLTHROUGH

#if PHP_VERSION_ID < 80100
/* Check if an array is a list */
static int zend_array_is_list(HashTable *myht)
{
    int i;
    i = myht ? zend_hash_num_elements(myht) : 0;
    if (i > 0) {
        zend_string *key;
        zend_ulong index, idx;

        if (HT_IS_PACKED(myht) && HT_IS_WITHOUT_HOLES(myht)) {
            return 1;
        }

        idx = 0;
        ZEND_HASH_FOREACH_KEY(myht, index, key) {
            if (key) {
                return 0;
            } else {
                if (index != idx) {
                    return 0;
                }
            }
            idx++;
        } ZEND_HASH_FOREACH_END();
    }

    return 1;
}
#endif

#if PHP_VERSION_ID < 80200
static zend_always_inline bool zend_string_equals_cstr(const zend_string *s1, const char *s2, size_t s2_length)
{
    return ZSTR_LEN(s1) == s2_length && !memcmp(ZSTR_VAL(s1), s2, s2_length);
}
#endif

#endif //SIMDJSON_COMPATIBILITY_H
