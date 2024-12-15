/*
  +----------------------------------------------------------------------+
  | simdjson_php                                                         |
  +----------------------------------------------------------------------+
  | This source file is subject to version 2.0 of the Apache license,    |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.apache.org/licenses/LICENSE-2.0.html                      |
  +----------------------------------------------------------------------+
  | Author: Jinxi Wang  <1054636713@qq.com>                              |
  | Author: Jakub Onderka <jakub.onderka@qmail.com>                      |
  +----------------------------------------------------------------------+
*/


extern "C" {
#include <ext/spl/spl_exceptions.h>
#include <Zend/zend_exceptions.h>
#include "php.h"
#include "php_simdjson.h"
}

#include "simdjson.h"
#include "simdjson_decoder_defs.h"
#include "simdjson_compatibility.h"

#define SIMDJSON_PHP_TRY(EXPR) { auto _err = (EXPR); if (UNEXPECTED(_err)) { return _err; } }

#define SIMDJSON_DEPTH_CHECK_THRESHOLD 100000

PHP_SIMDJSON_API const char* php_simdjson_error_msg(simdjson_php_error_code error) {
    switch (error) {
        case SIMDJSON_PHP_ERR_KEY_COUNT_NOT_COUNTABLE:
            return "JSON pointer refers to a value that cannot be counted";
        case SIMDJSON_PHP_ERR_INVALID_PHP_PROPERTY:
            return "Invalid property name";
        default:
            return simdjson::error_message((simdjson::error_code) error);
    }
}

PHP_SIMDJSON_API void php_simdjson_throw_jsonexception(simdjson_php_error_code error) {
    zend_throw_exception(simdjson_exception_ce, php_simdjson_error_msg(error), (zend_long) error);
}

static inline simdjson::simdjson_result<simdjson::dom::element>
get_key_with_optional_prefix(simdjson::dom::element &doc, std::string_view json_pointer) {
    /* https://www.rfc-editor.org/rfc/rfc6901.html */
    /* TODO: Deprecate in a subsequent minor release and remove in a major release to comply with the standard. */
    auto std_pointer = ((!json_pointer.empty() && json_pointer[0] != '/') ? "/" : "") + std::string(json_pointer.begin(), json_pointer.end());
    return doc.at_pointer(std_pointer);
}

/** Init packed array with expected size */
static zend_always_inline zend_array* simdjson_init_packed_array(zval *zv, uint32_t size) {
    zend_array *arr;
    array_init_size(zv, size);
    arr = Z_ARR_P(zv);
    zend_hash_real_init_packed(arr);
    return arr;
}

/** Decoded string from JSON must be always UTF-8 valid, so we can provide proper flag to zend_string */
static zend_always_inline zend_string* simdjson_string_init(const char* buf, const size_t len) {
    zend_string *str = zend_string_init(buf, len, 0);
    GC_ADD_FLAGS(str, IS_STR_VALID_UTF8);
    return str;
}

static simdjson::error_code
build_parsed_json_cust(simdjson_php_parser* parser, simdjson::dom::element &doc, const char *buf, size_t len, bool realloc_if_needed,
                       size_t depth = simdjson::DEFAULT_MAX_DEPTH) {
    if (UNEXPECTED(depth > SIMDJSON_DEPTH_CHECK_THRESHOLD) && depth > len && depth > parser->parser.max_depth()) {
        /*
         * Choose the depth in a way that both avoids frequent reallocations
         * and avoids excessive amounts of wasted memory beyond multiples of the largest string ever decoded.
         *
         * If the depth is already sufficient to parse a string of length `len`,
         * then use the parser's previous depth.
         *
         * Precondition: depth > len
         * Postcondition: depth <= original_depth && depth > len
         */
        if (len < SIMDJSON_DEPTH_CHECK_THRESHOLD) {
            depth = SIMDJSON_DEPTH_CHECK_THRESHOLD;
        } else if (depth > len * 2) {
            // In callers, simdjson_validate_depth ensures depth <= SIMDJSON_MAX_DEPTH (which is <= SIZE_MAX/8),
            // so len * 2 is even smaller than the previous depth and won't overflow.
            depth = len * 2;
        }
    }

    SIMDJSON_PHP_TRY(parser->parser.allocate(len, depth));
    SIMDJSON_PHP_TRY(parser->parser.parse(buf, len, realloc_if_needed).get(doc));

    return simdjson::SUCCESS;
}

static zend_always_inline void simdjson_set_zval_to_string(zval *v, const char *buf, size_t len) {
    if (len <= 1) {
        /*
        A note on performance benefits of the use of interned strings here and elsewhere:

        - PHP doesn't need to allocate a temporary string and initialize it
        - PHP doesn't need to free the temporary string
        - PHP doesn't need to compute the hash of the temporary string
        - Memory usage is reduced because the string representation is reused
        - String comparisons are faster when the strings are the exact same pointer.
        - CPU caches may already have this interned string
        - If all array keys are interned strings, then php can skip the step of
          freeing array keys when garbage collecting the array.
         */
        zend_string *key = len == 1 ? ZSTR_CHAR((unsigned char)buf[0]) : ZSTR_EMPTY_ALLOC();
        ZVAL_INTERNED_STR(v, key);
        return;
    }
    ZVAL_STRINGL(v, buf, len);
}

#if PHP_VERSION_ID >= 80200
// Exact copy of PHP method zend_hash_str_find_bucket that is not exported
static zend_always_inline Bucket *simdjson_zend_hash_str_find_bucket(const HashTable *ht, const char *str, size_t len, zend_ulong h)
{
	uint32_t nIndex;
	uint32_t idx;
	Bucket *p, *arData;

	arData = ht->arData;
	nIndex = h | ht->nTableMask;
	idx = HT_HASH_EX(arData, nIndex);
	while (idx != HT_INVALID_IDX) {
		ZEND_ASSERT(idx < HT_IDX_TO_HASH(ht->nTableSize));
		p = HT_HASH_TO_BUCKET_EX(arData, idx);
		if ((p->h == h)
			 && p->key
			 && zend_string_equals_cstr(p->key, str, len)) {
			return p;
		}
		idx = Z_NEXT(p->val);
	}
	return NULL;
}

/**
 * Optimised variant _zend_hash_str_add_or_update_i that removes a lof of redundant checks that are not necessary
 * when adding new item to initialized known hash array that is already allocated to required size
 * Requirements:
 *  - initialized array as zend_hash_real_init_mixed
 *  - exact size must be known in advance
 */
static zend_always_inline void simdjson_zend_hash_str_add_or_update(HashTable *ht, const char *str, size_t len, zval *pData)
{
    uint32_t nIndex;
    uint32_t idx;
    Bucket *p;
    zend_ulong h;

    // Check if array is initialized with proper flags and size
    // This checks are removed in production code
    ZEND_ASSERT(HT_FLAGS(ht) & ~HASH_FLAG_UNINITIALIZED);
    ZEND_ASSERT(HT_FLAGS(ht) & ~HASH_FLAG_PACKED);
    ZEND_ASSERT(ht->nNumUsed < ht->nTableSize);

    // Compute key hash
    h = zend_inline_hash_func(str, len);

    p = simdjson_zend_hash_str_find_bucket(ht, str, len, h);
    if (UNEXPECTED(p)) { // Key already exists, replace value
        zval *data;
        ZEND_ASSERT(&p->val != pData);
        data = &p->val;
        if (ht->pDestructor) {
            ht->pDestructor(data);
        }
        ZVAL_COPY_VALUE(data, pData);
    } else {
        idx = ht->nNumUsed++;
        ht->nNumOfElements++;
        p = ht->arData + idx;
        p->key = simdjson_string_init(str, len); // initialize new string for key
        p->h = ZSTR_H(p->key) = h;
        HT_FLAGS(ht) &= ~HASH_FLAG_STATIC_KEYS;
        ZVAL_COPY_VALUE(&p->val, pData);
        nIndex = h | ht->nTableMask;
        Z_NEXT(p->val) = HT_HASH(ht, nIndex);
        HT_HASH(ht, nIndex) = HT_IDX_TO_HASH(idx);
	}
}
#endif // PHP_VERSION_ID >= 80200

// Initialize mixed array with exact size (in PHP terminology mixed array is hash)
static zend_always_inline zend_array* simdjson_init_mixed_array(zval *zv, uint32_t size) {
    zend_array *arr;
    array_init_size(zv, size);
    arr = Z_ARR_P(zv);
 #if PHP_VERSION_ID >= 80200
    zend_hash_real_init_mixed(arr); // Expect mixed array
 #endif
    return arr;
}

static zend_always_inline void simdjson_add_key_to_symtable(HashTable *ht, const char *buf, size_t len, zval *value) {
#if PHP_VERSION_ID >= 80200
    zend_ulong idx;
    if (UNEXPECTED(ZEND_HANDLE_NUMERIC_STR(buf, len, idx))) {
        zend_hash_index_update(ht, idx, value); // if index is inter in string format, use integer as index
    } else if (UNEXPECTED(len <= 1)) {
        // Use interned string
        zend_string *key = len == 1 ? ZSTR_CHAR((unsigned char)buf[0]) : ZSTR_EMPTY_ALLOC();
        zend_hash_update(ht, key, value);
    } else {
        simdjson_zend_hash_str_add_or_update(ht, buf, len, value);
    }
#else
    if (len <= 1) {
        /* Look up the interned string (i.e. not reference counted) */
        zend_string *key = len == 1 ? ZSTR_CHAR((unsigned char)buf[0]) : ZSTR_EMPTY_ALLOC();
        /* Add the key or update the existing value of the key. */
        zend_symtable_update(ht, key, value);
        /* zend_string_release_ex is a no-op for interned strings */
        return;
    }
    zend_string *key = simdjson_string_init(buf, len);
    zend_symtable_update(ht, key, value);
    /* Release the reference counted key */
    zend_string_release_ex(key, 0);
#endif
}

static zend_always_inline void simdjson_set_zval_to_int64(zval *zv, const int64_t value) {
#if SIZEOF_ZEND_LONG < 8
    if (value != (zend_long)value) {
        ZVAL_DOUBLE(zv, value);
        return;
    }
#endif
    ZVAL_LONG(zv, value);
}

static simdjson_php_error_code create_array(simdjson::dom::element element, zval *return_value) /* {{{ */ {
    switch (element.type()) {
        //ASCII sort
        case simdjson::dom::element_type::STRING :
            simdjson_set_zval_to_string(return_value, element.get_c_str().value_unsafe(), element.get_string_length().value_unsafe());
            break;
        case simdjson::dom::element_type::INT64 :
            simdjson_set_zval_to_int64(return_value, element.get_int64().value_unsafe());
            break;
            /* UINT64 is used for positive values exceeding INT64_MAX */
        case simdjson::dom::element_type::UINT64 :
            ZVAL_DOUBLE(return_value, (double)element.get_uint64().value_unsafe());
            break;
        case simdjson::dom::element_type::DOUBLE :
            ZVAL_DOUBLE(return_value, element.get_double().value_unsafe());
            break;
        case simdjson::dom::element_type::BOOL :
            ZVAL_BOOL(return_value, element.get_bool().value_unsafe());
            break;
        case simdjson::dom::element_type::NULL_VALUE :
            ZVAL_NULL(return_value);
            break;
        case simdjson::dom::element_type::ARRAY : {
            const auto json_array = element.get_array().value_unsafe();
            if (json_array.size() == 0) {
                /* Reuse the immutable empty array to save memory */
                ZVAL_EMPTY_ARRAY(return_value);
                break;
            }

            zend_array *arr = simdjson_init_packed_array(return_value, json_array.size());
#if PHP_VERSION_ID >= 80200
            ZEND_HASH_FILL_PACKED(arr) {
                for (simdjson::dom::element child : json_array) {
                    create_array(child, __fill_val);
                    ZEND_HASH_FILL_NEXT();
                }
            } ZEND_HASH_FILL_END();
#else
            for (simdjson::dom::element child : json_array) {
                zval array_element;
                create_array(child, &array_element);
                zend_hash_next_index_insert_new(arr, &array_element);
            }
#endif
            break;
        }
        case simdjson::dom::element_type::OBJECT : {
            const auto json_object = element.get_object().value_unsafe();
            if (json_object.size() == 0) {
                /* Reuse the immutable empty array to save memory */
                ZVAL_EMPTY_ARRAY(return_value);
                break;
            }

            zend_array *arr = simdjson_init_mixed_array(return_value, json_object.size());

            for (simdjson::dom::key_value_pair field : json_object) {
                zval array_element;
                create_array(field.value, &array_element);
                simdjson_add_key_to_symtable(arr, field.key.data(), field.key.size(), &array_element);
            }
            break;
        }
        EMPTY_SWITCH_DEFAULT_CASE();
    }

    return simdjson::SUCCESS;
}

/* }}} */

static simdjson_php_error_code create_object(simdjson::dom::element element, zval *return_value) /* {{{ */ {
    switch (element.type()) {
        //ASCII sort
        case simdjson::dom::element_type::STRING :
            simdjson_set_zval_to_string(return_value, element.get_c_str().value_unsafe(), element.get_string_length().value_unsafe());
            break;
        case simdjson::dom::element_type::INT64 :
            simdjson_set_zval_to_int64(return_value, element.get_int64().value_unsafe());
            break;
            /* UINT64 is used for positive values exceeding INT64_MAX */
        case simdjson::dom::element_type::UINT64 :
            ZVAL_DOUBLE(return_value, (double)element.get_uint64().value_unsafe());
            break;
        case simdjson::dom::element_type::DOUBLE :
            ZVAL_DOUBLE(return_value, element.get_double().value_unsafe());
            break;
        case simdjson::dom::element_type::BOOL :
            ZVAL_BOOL(return_value, element.get_bool().value_unsafe());
            break;
        case simdjson::dom::element_type::NULL_VALUE :
            ZVAL_NULL(return_value);
            break;
        case simdjson::dom::element_type::ARRAY : {
            const auto json_array = element.get_array().value_unsafe();
            if (json_array.size() == 0) {
                /* Reuse the immutable empty array to save memory */
                ZVAL_EMPTY_ARRAY(return_value);
                return simdjson::SUCCESS;
            }

            zend_array *arr = simdjson_init_packed_array(return_value, json_array.size());

            for (simdjson::dom::element child : json_array) {
                zval value;
                simdjson_php_error_code error = create_object(child, &value);
                if (UNEXPECTED(error)) {
                    zval_ptr_dtor(return_value);
                    ZVAL_NULL(return_value);
                    return error;
                }
                zend_hash_next_index_insert(arr, &value);
            }
            break;
        }
        case simdjson::dom::element_type::OBJECT : {
            const auto json_object = element.get_object().value_unsafe();
            object_init(return_value);
            zend_object *obj = Z_OBJ_P(return_value);

            for (simdjson::dom::key_value_pair field : json_object) {
                const char *data = field.key.data();
                size_t size = field.key.size();
				/* PHP 7.1 allowed using the empty string as a property of an object */
                if (UNEXPECTED(data[0] == '\0') && (PHP_VERSION_ID < 70100 || UNEXPECTED(size > 0))) {
                    zval_ptr_dtor(return_value);
                    ZVAL_NULL(return_value);
                    /* Use a number that won't be in the simdjson bindings */
                    return SIMDJSON_PHP_ERR_INVALID_PHP_PROPERTY;
                }
                zval value;
                simdjson_php_error_code error = create_object(field.value, &value);
                if (error) {
                    zval_ptr_dtor(return_value);
                    ZVAL_NULL(return_value);
                    return error;
                }

                /* Add the key to the object */
                zend_string *key;
                if (size <= 1) {
                    key = size == 1 ? ZSTR_CHAR((unsigned char)data[0]) : ZSTR_EMPTY_ALLOC();
                } else {
                    key = simdjson_string_init(data, size);
                }
                zend_std_write_property(obj, key, &value, NULL);
                zend_string_release_ex(key, 0);

                /* After the key is added to the object (incrementing the reference count) ,
                 * decrement the reference count of the value by one */
                zval_ptr_dtor_nogc(&value);
            }
            break;
        }
        EMPTY_SWITCH_DEFAULT_CASE();
    }
    return simdjson::SUCCESS;
}

/* }}} */

PHP_SIMDJSON_API simdjson_php_parser* php_simdjson_create_parser(void) /* {{{ */ {
    return new simdjson_php_parser();
}

PHP_SIMDJSON_API void php_simdjson_free_parser(simdjson_php_parser* parser) /* {{{ */ {
    delete parser;
}

PHP_SIMDJSON_API simdjson_php_error_code php_simdjson_validate(simdjson_php_parser* parser, const char *json, size_t len, size_t depth) /* {{{ */ {
    simdjson::dom::element doc;
    /* The depth is passed in to ensure this behaves the same way for the same arguments */
    return build_parsed_json_cust(parser, doc, json, len, true, depth);
}

/* }}} */

PHP_SIMDJSON_API simdjson_php_error_code php_simdjson_parse(simdjson_php_parser* parser, const char *json, size_t len, zval *return_value, bool associative, size_t depth) /* {{{ */ {
    simdjson::dom::element doc;

    SIMDJSON_PHP_TRY(build_parsed_json_cust(parser, doc, json, len, true, depth));

    if (associative) {
        return create_array(doc, return_value);
    } else {
        return create_object(doc, return_value);
    }
}
/* }}} */
PHP_SIMDJSON_API simdjson_php_error_code php_simdjson_key_value(simdjson_php_parser* parser, const char *json, size_t len, const char *key, zval *return_value, bool associative,
                              size_t depth) /* {{{ */ {
    simdjson::dom::element doc;
    simdjson::dom::element element;
    SIMDJSON_PHP_TRY(build_parsed_json_cust(parser, doc, json, len, true, depth));
    SIMDJSON_PHP_TRY(get_key_with_optional_prefix(doc, key).get(element));
    if (associative) {
        return create_array(element, return_value);
    } else {
        return create_object(element, return_value);
    }
}

/* }}} */

PHP_SIMDJSON_API simdjson_php_error_code php_simdjson_key_exists(simdjson_php_parser* parser, const char *json, size_t len, const char *key, size_t depth) /* {{{ */ {
    simdjson::dom::element doc;
    SIMDJSON_PHP_TRY(build_parsed_json_cust(parser, doc, json, len, true, depth));
    return get_key_with_optional_prefix(doc, key).error();
}

/* }}} */

PHP_SIMDJSON_API simdjson_php_error_code php_simdjson_key_count(simdjson_php_parser* parser, const char *json, size_t len, const char *key, zval *return_value, size_t depth, bool fail_if_uncountable) /* {{{ */ {
    simdjson::dom::element doc;
    simdjson::dom::element element;

    SIMDJSON_PHP_TRY(build_parsed_json_cust(parser, doc, json, len, true, depth));

    SIMDJSON_PHP_TRY(get_key_with_optional_prefix(doc, key).get(element));

    zend_long key_count;
    switch (element.type()) {
        //ASCII sort
        case simdjson::dom::element_type::ARRAY : {
            auto json_array = element.get_array().value_unsafe();
            key_count = zend_long(json_array.size());
            if (UNEXPECTED(key_count == 0xFFFFFF)) {
                /* The C simdjson library represents array sizes larger than 0xFFFFFF as 0xFFFFFF. */
                key_count = 0;
                for (auto it: json_array)  {
                    (void)it;
                    key_count++;
                }
                ZEND_ASSERT(key_count >= 0xFFFFFF);
            }
            break;
        }
        case simdjson::dom::element_type::OBJECT : {
            auto json_object = element.get_object().value_unsafe();
            key_count = zend_long(json_object.size());
            if (UNEXPECTED(key_count == 0xFFFFFF)) {
                /* The C simdjson library represents object sizes larger than 0xFFFFFF as 0xFFFFFF. */
                key_count = 0;
                for (auto it: json_object) {
                    (void)it;
                    key_count++;
                }
                ZEND_ASSERT(key_count >= 0xFFFFFF);
            }
            break;
        }
        default:
            return SIMDJSON_PHP_ERR_KEY_COUNT_NOT_COUNTABLE;
    }
    ZVAL_LONG(return_value, key_count);
    return simdjson::SUCCESS;
}

/* }}} */
