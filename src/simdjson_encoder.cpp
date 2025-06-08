/*
  +----------------------------------------------------------------------+
  | Copyright (c) The PHP Group                                          |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | https://www.php.net/license/3_01.txt                                 |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Omar Kilani <omar@php.net>                                   |
  |         Jakub Zelenka <bukka@php.net>                                |
  +----------------------------------------------------------------------+
*/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

extern "C" {
#include "php.h"
#include "zend_smart_str.h"
#include "zend_portability.h"
#include <zend_exceptions.h>
#include "ext/json/php_json.h" /* For php_json_serializable_ce */
#if PHP_VERSION_ID >= 80400
#include "zend_property_hooks.h"
#include "zend_lazy_objects.h"
#endif
}

#include "php_simdjson.h"
#include "simdjson_encoder.h"
#include "countlut.h"
#if defined(__SSE2__) || defined(__aarch64__) || defined(_M_ARM64)
#include "simdjson_vector8.h"
#endif
#if defined(__SSE2__)
#include "simdjson_avx2.h"
#endif
#include "simdjson.h"
#include "simdjson_compatibility.h"
#include "simdjson_smart_str.h"
#include "simdutf.h"

static zend_always_inline bool simdjson_check_stack_limit(void) {
#ifdef ZEND_CHECK_STACK_LIMIT
	return zend_call_stack_overflowed(EG(stack_limit));
#else
	return false;
#endif
}

static inline void simdjson_pretty_print_colon(smart_str *buf, const simdjson_encoder *encoder) {
	if (encoder->options & SIMDJSON_PRETTY_PRINT) {
		simdjson_smart_str_appendl(buf, ": ", 2);
	} else {
		simdjson_smart_str_appendc(buf, ':');
    }
}

static inline void simdjson_pretty_print_nl_ident(smart_str *buf, const simdjson_encoder *encoder) {
  	char *next;
	const char *whitespace = "\n                                ";

	if (encoder->options & SIMDJSON_PRETTY_PRINT) {
		next = simdjson_smart_str_extend(buf, 4 * encoder->depth + 1);
        if (EXPECTED(encoder->depth <= 8)) {
        	memcpy(next, whitespace, encoder->depth * 4 + 1);
        } else {
            memcpy(next, whitespace, 8 * 4 + 1);
        	next += 8 * 4 + 1;
			for (size_t i = 8; i < encoder->depth; ++i) {
	            memcpy(next, "    ", 4);
	            next += 4;
			}
        }
	}
}

static inline void simdjson_append_double(smart_str *buf, double d) {
    char *output = simdjson_smart_str_alloc(buf, 21);
    char *end = simdjson::internal::to_chars(output, nullptr, d);
    // HACK: simdjson to_chars method always add .0 at end of string. If output string contains '.0' at the end,
    // remove it to use the same behaviour as PHP php_gcvt
    if (*(end - 2) == '.' && *(end - 1) == '0') {
        end -= 2;
    }
    ZSTR_LEN(buf->s) += end - output;
}

static inline void simdjson_append_long(smart_str *buf, zend_long number) {
	char *output = simdjson_smart_str_alloc(buf, strlen("-9223372036854775807"));
	unsigned chars = simdjson_i64toa_countlut(number, output);
    ZSTR_LEN(buf->s) += chars;
}

#define SIMDJSON_HASH_PROTECT_RECURSION(_tmp_ht) \
	do { \
		if (EXPECTED(_tmp_ht)) { \
			GC_TRY_PROTECT_RECURSION(_tmp_ht); \
		} \
	} while (0)

#define SIMDJSON_HASH_UNPROTECT_RECURSION(_tmp_ht) \
	do { \
		if (EXPECTED(_tmp_ht)) { \
			GC_TRY_UNPROTECT_RECURSION(_tmp_ht); \
		} \
	} while (0)

// Specific implementation for faster encoding packed arrays
static zend_result simdjson_encode_packed_array(smart_str *buf, HashTable *table, simdjson_encoder *encoder) {
  	zval* data;
	zend_refcounted *recursion_rc = (zend_refcounted *)table;

    ZEND_ASSERT(recursion_rc != NULL);

	if (GC_IS_RECURSIVE(recursion_rc)) {
		encoder->error_code = SIMDJSON_ERROR_RECURSION;
		return FAILURE;
	}

	SIMDJSON_HASH_PROTECT_RECURSION(recursion_rc);

	simdjson_smart_str_appendc(buf, '[');
	++encoder->depth;

	ZEND_HASH_PACKED_FOREACH_VAL(table, data) {
		simdjson_pretty_print_nl_ident(buf, encoder);
		if (UNEXPECTED(simdjson_encode_zval(buf, data, encoder) == FAILURE)) {
			SIMDJSON_HASH_UNPROTECT_RECURSION(recursion_rc);
        	return FAILURE;
        }
		simdjson_smart_str_appendc(buf, ',');
    } ZEND_HASH_FOREACH_END();

    ZSTR_LEN(buf->s)--; // remove last comma

	SIMDJSON_HASH_UNPROTECT_RECURSION(recursion_rc);

	if (UNEXPECTED(encoder->depth > encoder->max_depth)) {
		encoder->error_code = SIMDJSON_ERROR_DEPTH;
		return FAILURE;
	}
	--encoder->depth;

	simdjson_pretty_print_nl_ident(buf, encoder);
	simdjson_smart_str_appendc(buf, ']');

    return SUCCESS;
}

static zend_result simdjson_encode_mixed_array(smart_str *buf, HashTable *table, simdjson_encoder *encoder) {
	int need_comma = 0;
	zend_string *key;
	zval *data;
	zend_ulong index;
	zend_refcounted *recursion_rc = (zend_refcounted *)table;

    ZEND_ASSERT(recursion_rc != NULL);

	if (GC_IS_RECURSIVE(recursion_rc)) {
		encoder->error_code = SIMDJSON_ERROR_RECURSION;
		return FAILURE;
	}

	SIMDJSON_HASH_PROTECT_RECURSION(recursion_rc);

	simdjson_smart_str_appendc(buf, '{');
	++encoder->depth;

	ZEND_HASH_FOREACH_KEY_VAL_IND(table, index, key, data) {
		if (need_comma) {
			simdjson_smart_str_appendc(buf, ',');
		} else {
			need_comma = 1;
		}

		simdjson_pretty_print_nl_ident(buf, encoder);

		if (EXPECTED(key)) {
			if (UNEXPECTED(simdjson_escape_string(buf, key, encoder) == FAILURE)) {
				SIMDJSON_HASH_UNPROTECT_RECURSION(recursion_rc);
				return FAILURE;
			}
		} else {
			simdjson_smart_str_appendc(buf, '"');
			simdjson_append_long(buf, (zend_long) index);
			simdjson_smart_str_appendc(buf, '"');
		}

		simdjson_pretty_print_colon(buf, encoder);

		if (UNEXPECTED(simdjson_encode_zval(buf, data, encoder) == FAILURE)) {
			SIMDJSON_HASH_UNPROTECT_RECURSION(recursion_rc);
			return FAILURE;
		}
	} ZEND_HASH_FOREACH_END();

	SIMDJSON_HASH_UNPROTECT_RECURSION(recursion_rc);

	if (UNEXPECTED(encoder->depth > encoder->max_depth)) {
		encoder->error_code = SIMDJSON_ERROR_DEPTH;
		return FAILURE;
	}
	--encoder->depth;

	/* Only keep closing bracket on same line for empty arrays/objects */
	if (need_comma) {
		simdjson_pretty_print_nl_ident(buf, encoder);
	}
	simdjson_smart_str_appendc(buf, '}');

	return SUCCESS;
}

static zend_result simdjson_encode_simple_object(smart_str *buf, zval *val, simdjson_encoder *encoder) {
	int need_comma = 0;

	/* Optimized version without rebuilding properties HashTable */
	zend_object *obj = Z_OBJ_P(val);
	zend_class_entry *ce = obj->ce;
	zend_property_info *prop_info;
	zval *prop;

	if (GC_IS_RECURSIVE(obj)) {
		encoder->error_code = SIMDJSON_ERROR_RECURSION;
		return FAILURE;
	}

	SIMDJSON_HASH_PROTECT_RECURSION(obj);

	simdjson_smart_str_appendc(buf, '{');
	++encoder->depth;

	for (int i = 0; i < ce->default_properties_count; i++) {
		prop_info = ce->properties_info_table[i];
		if (!prop_info) {
			continue;
		}
		if (ZSTR_VAL(prop_info->name)[0] == '\0' && ZSTR_LEN(prop_info->name) > 0) {
			/* Skip protected and private members. */
			continue;
		}
		prop = OBJ_PROP(obj, prop_info->offset);
		if (Z_TYPE_P(prop) == IS_UNDEF) {
			continue;
		}

		if (need_comma) {
			simdjson_smart_str_appendc(buf, ',');
		} else {
			need_comma = 1;
		}

		simdjson_pretty_print_nl_ident(buf, encoder);

		if (simdjson_escape_string(buf, prop_info->name, encoder) == FAILURE) {
			SIMDJSON_HASH_UNPROTECT_RECURSION(obj);
			return FAILURE;
		}

		simdjson_pretty_print_colon(buf, encoder);

		if (simdjson_encode_zval(buf, prop, encoder) == FAILURE) {
			SIMDJSON_HASH_UNPROTECT_RECURSION(obj);
			return FAILURE;
		}
	}

	SIMDJSON_HASH_UNPROTECT_RECURSION(obj);
	if (encoder->depth > encoder->max_depth) {
		encoder->error_code = SIMDJSON_ERROR_DEPTH;
		return FAILURE;
	}
	--encoder->depth;

	if (need_comma) {
		simdjson_pretty_print_nl_ident(buf, encoder);
	}
	simdjson_smart_str_appendc(buf, '}');
	return SUCCESS;
}

static zend_always_inline bool simdjson_is_simple_object(zval *val) {
	return Z_OBJ_P(val)->properties == NULL
		&& Z_OBJ_HT_P(val)->get_properties_for == NULL
		&& Z_OBJ_HT_P(val)->get_properties == zend_std_get_properties
#if PHP_VERSION_ID >= 80400
		&& Z_OBJ_P(val)->ce->num_hooked_props == 0
 		&& !zend_object_is_lazy(Z_OBJ_P(val))
#endif
        ;
}

static zend_result simdjson_encode_array(smart_str *buf, zval *val, simdjson_encoder *encoder) {
	int need_comma = 0;
	HashTable *myht;
	zend_refcounted *recursion_rc;

	if (simdjson_check_stack_limit()) {
		encoder->error_code = SIMDJSON_ERROR_DEPTH;
		return FAILURE;
	}

	if (Z_TYPE_P(val) == IS_ARRAY) {
		myht = Z_ARRVAL_P(val);
        // Array is empty
		if (zend_hash_num_elements(myht) == 0) {
			simdjson_smart_str_appendl(buf, "[]", 2);
			return SUCCESS;
		}
        if (zend_array_is_list(myht)) {
        	return simdjson_encode_packed_array(buf, myht, encoder);
        } else {
        	return simdjson_encode_mixed_array(buf, myht, encoder);
        }
	}

    if (simdjson_is_simple_object(val)) {
		return simdjson_encode_simple_object(buf, val, encoder);
	}

	zend_object *obj = Z_OBJ_P(val);
	myht = zend_get_properties_for(val, ZEND_PROP_PURPOSE_JSON);
#if PHP_VERSION_ID >= 80400
	if (obj->ce->num_hooked_props == 0) {
		recursion_rc = (zend_refcounted *)myht;
	} else {
		/* Protecting the object itself is fine here because myht is temporary and can't be
		 * referenced from a different place in the object graph. */
		recursion_rc = (zend_refcounted *)obj;
	}
#else
    recursion_rc = (zend_refcounted *)myht;
#endif

	if (recursion_rc && GC_IS_RECURSIVE(recursion_rc)) {
		encoder->error_code = SIMDJSON_ERROR_RECURSION;
		zend_release_properties(myht);
		return FAILURE;
	}

	SIMDJSON_HASH_PROTECT_RECURSION(recursion_rc);

	simdjson_smart_str_appendc(buf, '{');

	++encoder->depth;

	uint32_t i = zend_hash_num_elements(myht);

	if (i > 0) {
		zend_string *key;
		zval *data;
		zend_ulong index;

		ZEND_HASH_FOREACH_KEY_VAL_IND(myht, index, key, data) {
			zval tmp;
			ZVAL_UNDEF(&tmp);

			if (key) {
				if (ZSTR_VAL(key)[0] == '\0' && ZSTR_LEN(key) > 0 && Z_TYPE_P(val) == IS_OBJECT) {
					/* Skip protected and private members. */
					continue;
				}

#if PHP_VERSION_ID >= 80400
				/* data is IS_PTR for properties with hooks. */
				if (UNEXPECTED(Z_TYPE_P(data) == IS_PTR)) {
					zend_property_info *prop_info = (zend_property_info*)Z_PTR_P(data);
					if ((prop_info->flags & ZEND_ACC_VIRTUAL) && !prop_info->hooks[ZEND_PROPERTY_HOOK_GET]) {
						continue;
					}
					zend_read_property_ex(prop_info->ce, Z_OBJ_P(val), prop_info->name, /* silent */ true, &tmp);
					if (EG(exception)) {
						SIMDJSON_HASH_UNPROTECT_RECURSION(recursion_rc);
						zend_release_properties(myht);
						return FAILURE;
					}
					data = &tmp;
				}
#endif

				if (need_comma) {
					simdjson_smart_str_appendc(buf, ',');
				} else {
					need_comma = 1;
				}

				simdjson_pretty_print_nl_ident(buf, encoder);

				if (simdjson_escape_string(buf, key, encoder) == FAILURE) {
					SIMDJSON_HASH_UNPROTECT_RECURSION(recursion_rc);
					zend_release_properties(myht);
					return FAILURE;
				}
			} else {
				if (need_comma) {
					simdjson_smart_str_appendc(buf, ',');
				} else {
					need_comma = 1;
				}

				simdjson_pretty_print_nl_ident(buf, encoder);

				simdjson_smart_str_appendc(buf, '"');
				simdjson_append_long(buf, (zend_long) index);
				simdjson_smart_str_appendc(buf, '"');
			}

			simdjson_pretty_print_colon(buf, encoder);

			if (simdjson_encode_zval(buf, data, encoder) == FAILURE) {
				SIMDJSON_HASH_UNPROTECT_RECURSION(recursion_rc);
				zend_release_properties(myht);
				zval_ptr_dtor(&tmp);
				return FAILURE;
			}
			zval_ptr_dtor(&tmp);
		} ZEND_HASH_FOREACH_END();
	}

	SIMDJSON_HASH_UNPROTECT_RECURSION(recursion_rc);

	if (encoder->depth > encoder->max_depth) {
		encoder->error_code = SIMDJSON_ERROR_DEPTH;
		zend_release_properties(myht);
		return FAILURE;
	}
	--encoder->depth;

	/* Only keep closing bracket on same line for empty arrays/objects */
	if (need_comma) {
		simdjson_pretty_print_nl_ident(buf, encoder);
	}

	simdjson_smart_str_appendc(buf, '}');

	zend_release_properties(myht);
	return SUCCESS;
}

static zend_always_inline size_t simdjson_append_escape(char *buf, char c) {
	auto append = simdjson_escape[c];
	memcpy(buf, append.str, SIMDJSON_ENCODER_ESCAPE_LENGTH);
	return append.len;
}

#define SIDMJSON_ZSTR_ALLOC(_size) \
    do { \
        auto _new_end = _size + output; \
        if (UNEXPECTED(_new_end > ZSTR_VAL(buf->s) + buf->a)) { \
            ZSTR_LEN(buf->s) = output - ZSTR_VAL(buf->s); \
            smart_str_erealloc(buf, ZSTR_LEN(buf->s) + _size); \
            output = ZSTR_VAL(buf->s) + ZSTR_LEN(buf->s); \
        } \
    } while (0); \

#if defined(__SSE2__) || defined(__aarch64__) || defined(_M_ARM64)
template<typename T>
static zend_always_inline void simdjson_escape_long_string(smart_str *buf, const char *s, size_t len) {
    T chunk;
    const char* start = s;
    const size_t vlen = len & (int) (~(sizeof(chunk) - 1)); // max length that can be processed in chunk mode
    char *output;

	output = simdjson_smart_str_alloc(buf, len + 2);
    *output++ = '"';

    // Iterate input string in chunks
	while (s < start + vlen) {
		// Load chars to vector
		chunk.load((const uint8_t *) s);
		// Check chunk if contains char that needs to be escaped
        auto needs_escaping = chunk.needs_escaping();
		if (EXPECTED(!needs_escaping)) {
            // If no escape char found, store chunk in output buffer and move buffer pointer
            ZEND_ASSERT(output + sizeof(chunk) <= ZSTR_VAL(buf->s) + buf->a);
			chunk.store((uint8_t*)output);
            output += sizeof(chunk);
            s += sizeof(chunk);
		} else {
            // Allocate enough space for escaped chunk + space for rest of unescaped string
            SIDMJSON_ZSTR_ALLOC((sizeof(chunk) * SIMDJSON_ENCODER_ESCAPE_LENGTH) + (start + len - s));
            // Copy first bytes that do not need escaping in chunk without checking
            auto j = chunk.escape_index(needs_escaping);
            memcpy(output, s, j);
            output += j;
            s += j;

            // Process rest of chunk char by char and escape required char
            for (; j < sizeof(chunk); j++) {
                char c = *s++;
                if (EXPECTED(simdjson_need_escaping[(uint8_t)c] == 0)) {
                    *output++ = c;
                } else {
                    output += simdjson_append_escape(output, c);
                }
            }
        }
	}

    // Ensure that buf contains enough space that we can call unsafe methods
    SIDMJSON_ZSTR_ALLOC(sizeof(chunk) * SIMDJSON_ENCODER_ESCAPE_LENGTH + 1);

    // Finish last chars of string
    while (s < start + len) {
		char c = *s++;
		if (EXPECTED(simdjson_need_escaping[(uint8_t)c] == 0)) {
			*output++ = c;
		} else {
			output += simdjson_append_escape(output, c);
		}
	}
    *output++ = '"';

    ZSTR_LEN(buf->s) = output - ZSTR_VAL(buf->s);
}
#endif

#ifdef __SSE2__
static zend_always_inline bool simdjson_avx2_supported() {
#ifdef __AVX2__
    return true;
#endif
#ifdef __builtin_cpu_supports
    return __builtin_cpu_supports("avx2"); // check support in runtime
#endif

	int cpuInfo[4];
	__cpuid(cpuInfo, 0);
	int nIds = cpuInfo[0];

	if (nIds >= 7) {
		__cpuidex(cpuInfo, 7, 0);
		return (cpuInfo[1] & (1 << 5)) != 0;
	}

	return false;
}

TARGET_AVX2 static inline void simdjson_escape_long_string_avx2(smart_str *buf, const char *s, size_t len) {
	return simdjson_escape_long_string<simdjson_avx2>(buf, s, len);
}
#endif

static zend_always_inline void simdjson_escape_short_string(smart_str *buf, const char *s, size_t len) {
    const char *end = s + len;

    // For short strings allocate maximum possible string length, so we can write directly to output buffer
    char *output = simdjson_smart_str_alloc(buf, len * 6 + 4);

    *output++ = '"';
    while (s < end) {
        char c = *s++;
        if (EXPECTED(simdjson_need_escaping[(uint8_t)c] == 0)) {
            *output++ = c;
        } else {
            output += simdjson_append_escape(output, c);
        }
    }
    *output++ = '"';

    ZSTR_LEN(buf->s) = output - ZSTR_VAL(buf->s);
}

/* valid as single byte character or leading byte */
#define utf8_lead(c)  ((c) < 0x80 || ((c) >= 0xC2 && (c) <= 0xF4))
/* whether it's actually valid depends on other stuff;
 * this macro cannot check for non-shortest forms, surrogates or
 * code points above 0x10FFFF */
#define utf8_trail(c) ((c) >= 0x80 && (c) <= 0xBF)

// Simplified version of php_next_utf8_char
static unsigned int simdjson_get_next_char(const unsigned char *str, size_t str_len) {
	if (str_len < 1)
		return 1;

    /* We'll follow strategy 2. from section 3.6.1 of UTR #36:
     * "In a reported illegal byte sequence, do not include any
     *  non-initial byte that encodes a valid character or is a leading
     *  byte for a valid sequence." */
    unsigned char c;
    c = str[0];
    if (c < 0x80 || c < 0xc2) {
        return 1;
    } else if (c < 0xe0) {
        if (str_len < 2)
            return 1;

        if (!utf8_trail(str[1])) {
            return utf8_lead(str[1]) ? 1 : 2;
        }
        return 2;
    } else if (c < 0xf0) {
        size_t avail = str_len;

        if (avail < 3 ||
                !utf8_trail(str[1]) || !utf8_trail(str[2])) {
            if (avail < 2 || utf8_lead(str[1]))
                return 1;
            else if (avail < 3 || utf8_lead(str[2]))
                return 2;
            else
                return 3;
        }

        return 3;
    } else if (c < 0xf5) {
        size_t avail = str_len;

        if (avail < 4 ||
                !utf8_trail(str[1]) || !utf8_trail(str[2]) ||
                !utf8_trail(str[3])) {
            if (avail < 2 || utf8_lead(str[1]))
                return 1;
            else if (avail < 3 || utf8_lead(str[2]))
                return 2;
            else if (avail < 4 || utf8_lead(str[3]))
                return 3;
            else
                return 4;
        }

        return 4;
    } else {
        return 1;
    }
}

static void simdjson_escape_substitute_string(smart_str *buf, const char *s, size_t len, bool substitute) {
    const char *end = s + len;

    char* output = simdjson_smart_str_alloc(buf, len + 2);
    *output++ = '"';

    while (s < end) {
        simdutf::result res = simdutf::validate_utf8_with_errors(s, end - s);
        if (res.error == simdutf::error_code::SUCCESS) {
            break;
        }
        // Escape string that is considered valid
        SIDMJSON_ZSTR_ALLOC(res.count * 6 + 4);
        const char* last_char = s + res.count;
        while (s < last_char) {
            char c = *s++;
            if (EXPECTED(simdjson_need_escaping[(uint8_t)c] == 0)) {
                *output++ = c;
            } else {
                output += simdjson_append_escape(output, c);
            }
        }
        if (substitute) {
            // Add replacement char
            memcpy(output, "\xef\xbf\xbd", 3);
            output += 3;
        }
        // Compute how much chars we need to skip
        s += simdjson_get_next_char((unsigned char *)s, end - s);
    }

    SIDMJSON_ZSTR_ALLOC((end - s) * 6 + 4);
    while (s < end) {
        char c = *s++;
        if (EXPECTED(simdjson_need_escaping[(uint8_t)c] == 0)) {
            *output++ = c;
        } else {
            output += simdjson_append_escape(output, c);
        }
    }

    *output++ = '"';

    ZSTR_LEN(buf->s) = output - ZSTR_VAL(buf->s);
}

static zend_result simdjson_escape_string(smart_str *buf, zend_string *str, simdjson_encoder *encoder) {
	size_t len = ZSTR_LEN(str);
    const char *s = ZSTR_VAL(str);

	if (len == 0) {
		simdjson_smart_str_appendl(buf, "\"\"", 2);
		return SUCCESS;
	}

	// Check if string is valid UTF-8 string
	if (!ZSTR_IS_VALID_UTF8(str)) {
	    if (EXPECTED(simdutf::validate_utf8(s, len))) {
	        // Mark string as valid UTF-8
        	GC_ADD_FLAGS(str, IS_STR_VALID_UTF8);
	    } else {
            if (encoder->options & SIMDJSON_INVALID_UTF8_SUBSTITUTE || encoder->options & SIMDJSON_INVALID_UTF8_IGNORE) {
                simdjson_escape_substitute_string(buf, s, len, encoder->options & SIMDJSON_INVALID_UTF8_SUBSTITUTE);
                return SUCCESS;
            }
            encoder->error_code = SIMDJSON_ERROR_UTF8;
            return FAILURE;
		}
    }

#ifdef __SSE2__
   if (len >= sizeof(simdjson_avx2) && simdjson_avx2_supported()) {
     	simdjson_escape_long_string_avx2(buf, s, len);
        return SUCCESS;
   }
#endif

#if defined(__SSE2__) || defined(__aarch64__) || defined(_M_ARM64)
    if (len >= sizeof(simdjson_vector8)) {
    	simdjson_escape_long_string<simdjson_vector8>(buf, s, len);
        return SUCCESS;
    }
#endif

    simdjson_escape_short_string(buf, s, len);

    return SUCCESS;
}

static void simdjson_encode_base64_object(smart_str *buf, const zval *val) {
    zend_string *binary_string = Z_STR_P(OBJ_PROP_NUM(Z_OBJ_P(val), 0));
    bool base64_url = Z_TYPE_INFO_P(OBJ_PROP_NUM(Z_OBJ_P(val), 1)) == IS_TRUE;
    auto options = base64_url ? simdutf::base64_url : simdutf::base64_default;

    // As we are sure that base64 encoded string is always valid UTF-8 and do not contain any char that need to be
    // escaped, so we can skip all checks and just directly copy encoded string to output buffer
    size_t encoded_length = simdutf::base64_length_from_binary(ZSTR_LEN(binary_string), options);
    char* output = simdjson_smart_str_extend(buf, encoded_length + 2);
    *output++ = '"';
    simdutf::binary_to_base64(ZSTR_VAL(binary_string), ZSTR_LEN(binary_string), output, options);
    output += encoded_length;
    *output = '"';
}

static zend_result simdjson_encode_serializable_object(smart_str *buf, zval *val, simdjson_encoder *encoder) {
	zend_class_entry *ce = Z_OBJCE_P(val);
	zend_object *obj = Z_OBJ_P(val);
	zval retval;
	zend_result return_code;

#if PHP_VERSION_ID >= 80300
	uint32_t *guard = zend_get_recursion_guard(obj);
	ZEND_ASSERT(guard != NULL);

	if (ZEND_GUARD_IS_RECURSIVE(guard, JSON)) {
		encoder->error_code = SIMDJSON_ERROR_RECURSION;
		return FAILURE;
	}

	ZEND_GUARD_PROTECT_RECURSION(guard, JSON);
#else
	HashTable* myht = Z_OBJPROP_P(val);

	if (myht && GC_IS_RECURSIVE(myht)) {
		encoder->error_code = SIMDJSON_ERROR_RECURSION;
		return FAILURE;
	}

	SIMDJSON_HASH_PROTECT_RECURSION(myht);
#endif

    zend_function *json_serialize_method = (zend_function*)zend_hash_find_ex_ptr(&ce->function_table, simdjson_json_serialize, 1);
    ZEND_ASSERT(json_serialize_method != NULL && "This should be guaranteed prior to calling this function");
    zend_call_known_instance_method_with_0_params(json_serialize_method, obj, &retval);
    /* An exception has occurred */
    if (Z_TYPE(retval) == IS_UNDEF) {
#if PHP_VERSION_ID >= 80300
		ZEND_GUARD_UNPROTECT_RECURSION(guard, JSON);
#else
		SIMDJSON_HASH_UNPROTECT_RECURSION(myht);
#endif
		return FAILURE;
	}

    if (Z_TYPE(retval) == IS_OBJECT && Z_OBJ(retval) == obj) {
		/* Handle the case where jsonSerialize does: return $this; by going straight to encode array */
#if PHP_VERSION_ID >= 80300
		ZEND_GUARD_UNPROTECT_RECURSION(guard, JSON);
#else
		SIMDJSON_HASH_UNPROTECT_RECURSION(myht);
#endif
		return_code = simdjson_encode_array(buf, &retval, encoder);
	} else {
		/* All other types, encode as normal */
		return_code = simdjson_encode_zval(buf, &retval, encoder);
#if PHP_VERSION_ID >= 80300
		ZEND_GUARD_UNPROTECT_RECURSION(guard, JSON);
#else
		SIMDJSON_HASH_UNPROTECT_RECURSION(myht);
#endif
	}

	zval_ptr_dtor(&retval);

	return return_code;
}

#if PHP_VERSION_ID >= 80100
// Copy of zend_enum_fetch_case_value
static zend_always_inline zval *simdjson_zend_enum_fetch_case_value(zend_object *zobj) {
	ZEND_ASSERT(zobj->ce->ce_flags & ZEND_ACC_ENUM);
	ZEND_ASSERT(zobj->ce->enum_backing_type != IS_UNDEF);
	return OBJ_PROP_NUM(zobj, 1);
}

static zend_result simdjson_encode_serializable_enum(smart_str *buf, zval *val, simdjson_encoder *encoder) {
	zend_class_entry *ce = Z_OBJCE_P(val);
	if (ce->enum_backing_type == IS_UNDEF) {
		encoder->error_code = SIMDJSON_ERROR_NON_BACKED_ENUM;
		return FAILURE;
	}

	zval *value_zv = simdjson_zend_enum_fetch_case_value(Z_OBJ_P(val));
	return simdjson_encode_zval(buf, value_zv, encoder);
}
#endif

zend_result simdjson_encode_zval(smart_str *buf, zval *val, simdjson_encoder *encoder) {
    // For simdjson_encode_to_stream method, write data to stream if buffer is larger than 64 kilobytes
    if (UNEXPECTED(encoder->stream != NULL && ZSTR_LEN(buf->s) >= 64 * 1024)) {
    	if (simdjson_encode_write_stream(buf, encoder) == FAILURE) {
          	return FAILURE;
    	}
    }

again:
	switch (Z_TYPE_P(val))
	{
		case IS_NULL:
			simdjson_smart_str_appendl(buf, "null", 4);
			break;

		case IS_TRUE:
			simdjson_smart_str_appendl(buf, "true", 4);
			break;
		case IS_FALSE:
			simdjson_smart_str_appendl(buf, "false", 5);
			break;

		case IS_LONG:
			simdjson_append_long(buf, Z_LVAL_P(val));
			break;

		case IS_DOUBLE:
			if (EXPECTED(!zend_isinf(Z_DVAL_P(val)) && !zend_isnan(Z_DVAL_P(val)))) {
				simdjson_append_double(buf, Z_DVAL_P(val));
			} else {
				encoder->error_code = SIMDJSON_ERROR_INF_OR_NAN;
                return FAILURE;
			}
			break;

		case IS_STRING:
			return simdjson_escape_string(buf, Z_STR_P(val), encoder);

		case IS_OBJECT:
			if (Z_OBJCE_P(val) == simdjson_base64_encode_ce) {
                simdjson_encode_base64_object(buf, val);
                return SUCCESS;
            }
			if (instanceof_function_slow(Z_OBJCE_P(val), php_json_serializable_ce)) {
				return simdjson_encode_serializable_object(buf, val, encoder);
			}
#if PHP_VERSION_ID >= 80100
			if (Z_OBJCE_P(val)->ce_flags & ZEND_ACC_ENUM) {
				return simdjson_encode_serializable_enum(buf, val, encoder);
			}
#endif
			/* fallthrough -- Non-serializable object */
			ZEND_FALLTHROUGH;
		case IS_ARRAY: {
			/* Avoid modifications (and potential freeing) of the array through a reference when a
			 * jsonSerialize() method is invoked. */
			zval zv;
			zend_result res;
			ZVAL_COPY(&zv, val);
			res = simdjson_encode_array(buf, &zv, encoder);
			zval_ptr_dtor_nogc(&zv);
			return res;
		}

		case IS_REFERENCE:
			val = Z_REFVAL_P(val);
			goto again;

		default:
			encoder->error_code = SIMDJSON_ERROR_UNSUPPORTED_TYPE;
			return FAILURE;
	}

	return SUCCESS;
}

zend_result simdjson_encode_write_stream(smart_str *buf, simdjson_encoder* encoder) {
	ssize_t numbytes = php_stream_write(encoder->stream, ZSTR_VAL(buf->s), ZSTR_LEN(buf->s));
	if (UNEXPECTED(numbytes < 0)) {
		encoder->error_code = SIMDJSON_ERROR_STREAM_WRITE;
		return FAILURE;
	}
	if (UNEXPECTED(numbytes != ZSTR_LEN(buf->s))) {
		php_error_docref(NULL, E_WARNING, "Only %zd of %zd bytes written, possibly out of free disk space", numbytes, ZSTR_LEN(buf->s));
		encoder->error_code = SIMDJSON_ERROR_STREAM_WRITE;
		return FAILURE;
    }
	ZSTR_LEN(buf->s) = 0; // cleanup buffer
    return SUCCESS;
}

const char* simdjson_encode_implementation() {
#ifdef __SSE2__
      if (simdjson_avx2_supported()) {
          return "AVX2";
      } else {
          return "SSE2";
      }
#elif defined(__aarch64__) || defined(_M_ARM64)
      return "ARM64 NEON";
#else
      return "Generic";
#endif
}
