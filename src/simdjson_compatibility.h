#ifndef SIMDJSON_COMPATIBILITY_H
#define SIMDJSON_COMPATIBILITY_H

#include "php.h"

// ZSTR_IS_VALID_UTF8 is available since PHP 8.3
#ifndef ZSTR_IS_VALID_UTF8
#define ZSTR_IS_VALID_UTF8(s) (GC_FLAGS(s) & IS_STR_VALID_UTF8)
#endif

// ZEND_HASH_PACKED_FOREACH_VAL is available since PHP 8.2
#ifndef ZEND_HASH_PACKED_FOREACH_VAL
#define	ZEND_HASH_PACKED_FOREACH_VAL(table, data) ZEND_HASH_FOREACH_VAL(table, data)
#endif

#if PHP_VERSION_ID < 70300
#define zend_string_release_ex(s, persistent) zend_string_release((s))
#endif

#ifndef ZVAL_EMPTY_ARRAY
#define ZVAL_EMPTY_ARRAY(value) array_init(value)
#endif

/* Define RETURN_THROWS macro in older php versions */
#ifndef RETURN_THROWS
#define RETURN_THROWS() do { ZEND_ASSERT(EG(exception)); (void) return_value; return; } while (0)
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

#endif //SIMDJSON_COMPATIBILITY_H
