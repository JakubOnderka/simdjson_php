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
  +----------------------------------------------------------------------+
*/

extern "C" {
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "zend_exceptions.h"
#include "zend_smart_str.h"
#include "main/SAPI.h"
#include "ext/standard/info.h"
#include "ext/spl/spl_exceptions.h"
#include "ext/json/php_json.h" /* For php_json_serializable_ce */

#include "php_simdjson.h"

/**
 * Both the declaration and the definition of PHP_SIMDJSON_API variables, functions must be within an 'extern "C"' block for Windows
 */
PHP_SIMDJSON_API zend_class_entry *simdjson_decoder_exception_ce;
PHP_SIMDJSON_API zend_class_entry *simdjson_encoder_exception_ce;
PHP_SIMDJSON_API zend_class_entry *simdjson_base64_encode_ce;

} /* end extern "C" */

/* C++ header file for simdjson_php helper methods/classes */
#include "src/simdjson_compatibility.h"
#include "src/simdjson_smart_str.h"
#include "src/simdjson_decoder_defs.h"
#include "src/simdjson_encoder.h"
/* Single header file from fork of simdjson C project (to imitate php's handling of infinity/overflowing integers in json_decode) */
#include "src/simdjson.h"
#include "src/simdutf.h"

#include "simdjson_arginfo.h"

static zend_string *simdjson_json_empty_array;

ZEND_DECLARE_MODULE_GLOBALS(simdjson);

#define SIMDJSON_G(v) ZEND_MODULE_GLOBALS_ACCESSOR(simdjson, v)

#define SIMDJSON_CAPACITY_RECLAIM_THRESHOLD 1024 * 1024 * 1 // 1MB
#define SIMDJSON_SHOULD_REUSE_PARSER(zstr_len) EXPECTED(zstr_len <= SIMDJSON_CAPACITY_RECLAIM_THRESHOLD)

// Get parser that can be reused multiple times to avoid allocation and deallocation
static simdjson_php_parser *simdjson_get_reused_parser() {
    simdjson_php_parser *parser = SIMDJSON_G(parser);
    if (parser == NULL) {
        parser = php_simdjson_create_parser();
        SIMDJSON_G(parser) = parser;
        ZEND_ASSERT(parser != NULL);
    }
    return parser;
}

PHP_SIMDJSON_API struct simdjson_php_parser *php_simdjson_get_default_singleton_parser(void) {
    return simdjson_get_reused_parser();
}

// The simdjson parser accepts strings with at most 32-bit lengths, for now.
#define SIMDJSON_MAX_DEPTH ((zend_long)((SIZE_MAX / 8) < (UINT32_MAX / 2) ? (SIZE_MAX / 8) : (UINT32_MAX / 2)))

static zend_always_inline bool simdjson_validate_depth(zend_long depth, const int arg_num) {
    if (UNEXPECTED(depth <= 0)) {
        zend_argument_value_error(arg_num, "must be greater than zero");
        return false;
    } else if (UNEXPECTED(depth > SIMDJSON_MAX_DEPTH)) {
        zend_argument_value_error(arg_num, "exceeds maximum allowed value of " ZEND_LONG_FMT, SIMDJSON_MAX_DEPTH);
        return false;
    }
    return true;
}

PHP_FUNCTION(simdjson_validate) {
    zend_string *json = NULL;
    zend_long depth = SIMDJSON_PARSE_DEFAULT_DEPTH;

    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_STR(json)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(depth)
    ZEND_PARSE_PARAMETERS_END();

    if (!simdjson_validate_depth(depth, 2)) {
        RETURN_THROWS();
    }

    simdjson_php_error_code error;
    if (SIMDJSON_SHOULD_REUSE_PARSER(ZSTR_LEN(json))) {
        error = php_simdjson_validate(simdjson_get_reused_parser(), json, depth);
    } else {
        simdjson_php_parser *simdjson_php_parser = php_simdjson_create_parser();
        error = php_simdjson_validate(simdjson_php_parser, json, depth);
        php_simdjson_free_parser(simdjson_php_parser);
    }

    ZVAL_BOOL(return_value, !error);
}

// Decode simple and common JSON values without allocating and using simdjson parser
static zend_always_inline bool simdjson_simple_decode(const char *json, size_t len, zval *return_value, bool associative) {
    // Empty object
    if (len == 2 && json[0] == '{' && json[1] == '}') {
        if (associative) {
            RETVAL_EMPTY_ARRAY();
        } else {
            object_init(return_value);
        }
        return true;
    }

    // Empty array
    if (len == 2 && json[0] == '[' && json[1] == ']') {
        RETVAL_EMPTY_ARRAY();
        return true;
    }

    if (len == 4 && memcmp(json, "true", 4) == 0) {
        RETVAL_TRUE;
        return true;
    } else if (len == 5 && memcmp(json, "false", 5) == 0) {
        RETVAL_FALSE;
        return true;
    }
    return false;
}

PHP_FUNCTION(simdjson_decode) {
    zend_bool associative = 0;
    zend_long depth = SIMDJSON_PARSE_DEFAULT_DEPTH;
    zend_string *json = NULL;

    ZEND_PARSE_PARAMETERS_START(1, 3)
        Z_PARAM_STR(json)
        Z_PARAM_OPTIONAL
        Z_PARAM_BOOL(associative)
        Z_PARAM_LONG(depth)
    ZEND_PARSE_PARAMETERS_END();

    if (!simdjson_validate_depth(depth, 3)) {
        RETURN_THROWS();
    }

    if (simdjson_simple_decode(ZSTR_VAL(json), ZSTR_LEN(json), return_value, associative)) {
        return;
    }

    simdjson_php_error_code error;
    if (SIMDJSON_SHOULD_REUSE_PARSER(ZSTR_LEN(json))) {
        error = php_simdjson_parse(simdjson_get_reused_parser(), json, return_value, associative, depth);
    } else {
        simdjson_php_parser *simdjson_php_parser = php_simdjson_create_parser();
        error = php_simdjson_parse(simdjson_php_parser, json, return_value, associative, depth);
        php_simdjson_free_parser(simdjson_php_parser);
    }

    if (UNEXPECTED(error)) {
        php_simdjson_throw_jsonexception(error);
        RETURN_THROWS();
    }
}

// Simplified version of _php_stream_copy_to_mem that allways allocated string with required padding and returns
// char* instead of of zend_string* to avoid unnecessary overhead
static char *simdjson_stream_copy_to_mem(php_stream *src, size_t *len) {
    ssize_t ret = 0;
    char *ptr;
    size_t buflen;
    int step = 8192;
    int min_room = 8192 / 4;
    php_stream_statbuf ssbuf;
    char* result;

    /* avoid many reallocs by allocating a good-sized chunk to begin with, if
     * we can.  Note that the stream may be filtered, in which case the stat
     * result may be inaccurate, as the filter may inflate or deflate the
     * number of bytes that we can read.  In order to avoid an upsize followed
     * by a downsize of the buffer, overestimate by the step size (which is
     * 8K).  */
    if (php_stream_stat(src, &ssbuf) == 0 && ssbuf.sb.st_size > 0) {
        buflen = ZEND_MM_ALIGNED_SIZE(MAX(ssbuf.sb.st_size - src->position, 0)) + step;
    } else {
        buflen = step;
    }

    result = (char*) emalloc(buflen);
    ptr = result;

    while ((ret = php_stream_read(src, ptr, buflen - *len)) > 0) {
        *len += ret;
        if (*len + min_room >= buflen) {
            buflen += step;
            result = (char*) erealloc(result, buflen);
            ptr = result + *len;
        } else {
            ptr += ret;
        }
    }

    if (*len == 0) {
        efree(result);
        return NULL;
    }

    if (UNEXPECTED(*len + simdjson::SIMDJSON_PADDING > buflen)) {
        result = (char*) erealloc(result, ZEND_MM_ALIGNED_SIZE(*len + simdjson::SIMDJSON_PADDING));
    }

#ifdef ZEND_DEBUG
    // Set padding to zero to make valgrind happy
    memset(ptr, 0, simdjson::SIMDJSON_PADDING);
#endif

    return result;
}

PHP_FUNCTION(simdjson_decode_from_stream) {
    zval *res;
    zend_bool associative = 0;
    zend_long depth = SIMDJSON_PARSE_DEFAULT_DEPTH;
    php_stream *stream;
    char *json;
    size_t len = 0;

    ZEND_PARSE_PARAMETERS_START(1, 3)
        Z_PARAM_RESOURCE(res)
        Z_PARAM_OPTIONAL
        Z_PARAM_BOOL(associative)
        Z_PARAM_LONG(depth)
    ZEND_PARSE_PARAMETERS_END();

    ZEND_ASSERT(Z_TYPE_P(res) == IS_RESOURCE);
    php_stream_from_res(stream, Z_RES_P(res));

    if (!simdjson_validate_depth(depth, 3)) {
        RETURN_THROWS();
    }

    if ((json = simdjson_stream_copy_to_mem(stream, &len)) == NULL) {
        php_simdjson_throw_jsonexception(simdjson::EMPTY);
        RETURN_THROWS();
    }

    if (simdjson_simple_decode(json, len, return_value, associative)) {
        efree(json);
        return;
    }

    simdjson_php_error_code error;
    if (SIMDJSON_SHOULD_REUSE_PARSER(len)) {
        error = php_simdjson_parse_buffer(simdjson_get_reused_parser(), json, len, return_value, associative, depth);
    } else {
        simdjson_php_parser *simdjson_php_parser = php_simdjson_create_parser();
        error = php_simdjson_parse_buffer(simdjson_php_parser, json, len, return_value, associative, depth);
        php_simdjson_free_parser(simdjson_php_parser);
    }

    efree(json);

    if (UNEXPECTED(error)) {
        php_simdjson_throw_jsonexception(error);
        RETURN_THROWS();
    }
}

PHP_FUNCTION(simdjson_key_value) {
    zend_string *json = NULL;
    zend_string *key = NULL;
    zend_bool associative = 0;
    zend_long depth = SIMDJSON_PARSE_DEFAULT_DEPTH;

    ZEND_PARSE_PARAMETERS_START(2, 4)
        Z_PARAM_STR(json)
        Z_PARAM_STR(key)
        Z_PARAM_OPTIONAL
        Z_PARAM_BOOL(associative)
        Z_PARAM_LONG(depth)
    ZEND_PARSE_PARAMETERS_END();

    if (!simdjson_validate_depth(depth, 4)) {
        RETURN_THROWS();
    }

    simdjson_php_error_code error;
    if (SIMDJSON_SHOULD_REUSE_PARSER(ZSTR_LEN(json))) {
        error = php_simdjson_key_value(simdjson_get_reused_parser(), json, ZSTR_VAL(key), return_value, associative, depth);
    } else {
        simdjson_php_parser *simdjson_php_parser = php_simdjson_create_parser();
        error = php_simdjson_key_value(simdjson_php_parser, json, ZSTR_VAL(key), return_value, associative, depth);
        php_simdjson_free_parser(simdjson_php_parser);
    }

    if (UNEXPECTED(error)) {
        php_simdjson_throw_jsonexception(error);
        RETURN_THROWS();
    }
}

PHP_FUNCTION(simdjson_key_count) {
    zend_string *json = NULL;
    zend_string *key = NULL;
    zend_long depth = SIMDJSON_PARSE_DEFAULT_DEPTH;
    bool throw_if_uncountable = false;

    ZEND_PARSE_PARAMETERS_START(2, 4)
        Z_PARAM_STR(json)
        Z_PARAM_STR(key)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(depth)
        Z_PARAM_BOOL(throw_if_uncountable)
    ZEND_PARSE_PARAMETERS_END();

    if (!simdjson_validate_depth(depth, 3)) {
        RETURN_THROWS();
    }

    simdjson_php_error_code error;
    if (SIMDJSON_SHOULD_REUSE_PARSER(ZSTR_LEN(json))) {
        error = php_simdjson_key_count(simdjson_get_reused_parser(), json, ZSTR_VAL(key), return_value, depth, throw_if_uncountable);
    } else {
        simdjson_php_parser *simdjson_php_parser = php_simdjson_create_parser();
        error = php_simdjson_key_count(simdjson_php_parser, json, ZSTR_VAL(key), return_value, depth, throw_if_uncountable);
        php_simdjson_free_parser(simdjson_php_parser);
    }

    if (UNEXPECTED(error)) {
        if (error == SIMDJSON_PHP_ERR_KEY_COUNT_NOT_COUNTABLE && !throw_if_uncountable) {
            RETURN_LONG(0);
        }
        php_simdjson_throw_jsonexception(error);
        RETURN_THROWS();
    }
}

PHP_FUNCTION(simdjson_key_exists) {
    zend_string *json = NULL;
    zend_string *key = NULL;
    zend_long depth = SIMDJSON_PARSE_DEFAULT_DEPTH;

    ZEND_PARSE_PARAMETERS_START(2, 3)
        Z_PARAM_STR(json)
        Z_PARAM_STR(key)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(depth)
    ZEND_PARSE_PARAMETERS_END();

    if (!simdjson_validate_depth(depth, 3)) {
        RETURN_THROWS();
    }

    simdjson_php_error_code error;
    if (SIMDJSON_SHOULD_REUSE_PARSER(ZSTR_LEN(json))) {
        error = php_simdjson_key_exists(simdjson_get_reused_parser(), json, ZSTR_VAL(key), depth);
    } else {
        simdjson_php_parser *simdjson_php_parser = php_simdjson_create_parser();
        error = php_simdjson_key_exists(simdjson_php_parser, json, ZSTR_VAL(key), depth);
        php_simdjson_free_parser(simdjson_php_parser);
    }

    switch (error) {
        case simdjson::SUCCESS:
            RETURN_TRUE;
        case simdjson::NO_SUCH_FIELD:
        case simdjson::INDEX_OUT_OF_BOUNDS:
        case simdjson::INCORRECT_TYPE:
            RETURN_FALSE;
        default:
            php_simdjson_throw_jsonexception(error);
            RETURN_THROWS();
    }
}

PHP_FUNCTION(simdjson_cleanup) {
    if (zend_parse_parameters_none() == FAILURE) {
        RETURN_THROWS();
    }

    simdjson_php_parser *parser = SIMDJSON_G(parser);
    if (EXPECTED(parser != NULL)) {
        php_simdjson_free_parser(parser);
        SIMDJSON_G(parser) = NULL;
    }
    RETURN_TRUE;
}

PHP_FUNCTION(simdjson_is_valid_utf8) {
    zend_string *string = NULL;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STR(string)
    ZEND_PARSE_PARAMETERS_END();

    // If string was already successfully validated, just return true
    if (ZSTR_IS_VALID_UTF8(string)) {
        RETURN_TRUE;
    }

    bool is_ok = simdutf::validate_utf8(ZSTR_VAL(string), ZSTR_LEN(string));
    if (EXPECTED(is_ok)) {
        // String is UTF-8 valid, so we can also set proper flag
        GC_ADD_FLAGS(string, IS_STR_VALID_UTF8);
    }
    RETURN_BOOL(is_ok);
}

static const char *simdjson_get_error_msg(simdjson_encoder_error_code error_code) {
    switch(error_code) {
        case SIMDJSON_ERROR_NONE:
            return "No error";
        case SIMDJSON_ERROR_DEPTH:
            return "Maximum stack depth exceeded";
        case SIMDJSON_ERROR_STATE_MISMATCH:
            return "State mismatch (invalid or malformed JSON)";
        case SIMDJSON_ERROR_CTRL_CHAR:
            return "Control character error, possibly incorrectly encoded";
        case SIMDJSON_ERROR_SYNTAX:
            return "Syntax error";
        case SIMDJSON_ERROR_UTF8:
            return "Malformed UTF-8 characters, possibly incorrectly encoded";
        case SIMDJSON_ERROR_RECURSION:
            return "Recursion detected";
        case SIMDJSON_ERROR_INF_OR_NAN:
            return "Inf and NaN cannot be JSON encoded";
        case SIMDJSON_ERROR_UNSUPPORTED_TYPE:
            return "Type is not supported";
        case SIMDJSON_ERROR_INVALID_PROPERTY_NAME:
            return "The decoded property name is invalid";
        case SIMDJSON_ERROR_UTF16:
            return "Single unpaired UTF-16 surrogate in unicode escape";
        case SIMDJSON_ERROR_NON_BACKED_ENUM:
            return "Non-backed enums have no default serialization";
        case SIMDJSON_ERROR_STREAM_WRITE:
            return "Stream write error";
        default:
            return "Unknown error";
    }
}

static zend_always_inline bool simdjson_validate_encode_depth(const zend_long depth, const int arg_num) {
    if (UNEXPECTED(depth <= 0)) {
        zend_argument_value_error(arg_num, "must be greater than 0");
        return false;
    }

    if (UNEXPECTED(depth > INT_MAX)) {
        zend_argument_value_error(arg_num, "must be less than %d", INT_MAX);
        return false;
    }

    return true;
}

#if PHP_VERSION_ID >= 80200
/** For simple types we can just return direct interned string without allocating new strings */
static zend_always_inline bool simdjson_encode_simple(const zval *parameter, zval *return_value) {
    switch (Z_TYPE_P(parameter)) {
        case IS_NULL:
            RETVAL_INTERNED_STR(ZSTR_KNOWN(ZEND_STR_NULL_LOWERCASE));
            return true;

        case IS_TRUE:
            RETVAL_INTERNED_STR(ZSTR_KNOWN(ZEND_STR_TRUE));
            return true;

        case IS_FALSE:
            RETVAL_INTERNED_STR(ZSTR_KNOWN(ZEND_STR_FALSE));
            return true;

        case IS_LONG:
            if (Z_LVAL_P(parameter) >= 0 && Z_LVAL_P(parameter) < 10) {
                RETVAL_INTERNED_STR(ZSTR_CHAR((unsigned char) '0' + Z_LVAL_P(parameter)));
                return true;
            }
            break;

        case IS_ARRAY:
            if (zend_hash_num_elements(Z_ARRVAL_P(parameter)) == 0) {
                RETVAL_INTERNED_STR(simdjson_json_empty_array);
                return true;
            }
            break;
    }

    return false;
}
#endif // PHP_VERSION_ID >= 80200

PHP_FUNCTION(simdjson_encode) {
    zval *parameter;
    simdjson_encoder encoder = {0};
    smart_str buf = {0};
    zend_long options = 0;
    zend_long depth = 512;

    ZEND_PARSE_PARAMETERS_START(1, 3)
        Z_PARAM_ZVAL(parameter)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(options)
        Z_PARAM_LONG(depth)
    ZEND_PARSE_PARAMETERS_END();

    if (!simdjson_validate_encode_depth(depth, 3)) {
        RETURN_THROWS();
    }

#if PHP_VERSION_ID >= 80200
    if (!(options & SIMDJSON_APPEND_NEWLINE) && simdjson_encode_simple(parameter, return_value)) {
        return;
    }
#endif

    encoder.max_depth = (int)depth;
    encoder.options = (int)options;
    // Allocate output buffer to smallest size, so we remove checks if buffer was allocated in simdjson_encode_zval method
    smart_str_erealloc(&buf, 200);
    simdjson_encode_zval(&buf, parameter, &encoder);

    if (UNEXPECTED(encoder.error_code != SIMDJSON_ERROR_NONE)) {
        efree(buf.s);
        zend_throw_exception(simdjson_encoder_exception_ce, simdjson_get_error_msg(encoder.error_code), encoder.error_code);
        RETURN_THROWS();
    }

    if (options & SIMDJSON_APPEND_NEWLINE) {
        simdjson_smart_str_appendc(&buf, '\n');
    }

    RETURN_NEW_STR(simdjson_smart_str_extract(&buf));
}

PHP_FUNCTION(simdjson_encode_to_stream) {
    zval *res;
    zval *parameter;
    simdjson_encoder encoder = {0};
    smart_str buf = {0};
    zend_long options = 0;
    zend_long depth = 512;
    php_stream *stream;

    ZEND_PARSE_PARAMETERS_START(2, 4)
        Z_PARAM_ZVAL(parameter)
        Z_PARAM_RESOURCE(res)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(options)
        Z_PARAM_LONG(depth)
    ZEND_PARSE_PARAMETERS_END();

    ZEND_ASSERT(Z_TYPE_P(res) == IS_RESOURCE);
    php_stream_from_res(stream, Z_RES_P(res));

    if (!simdjson_validate_encode_depth(depth, 4)) {
        RETURN_THROWS();
    }

    encoder.max_depth = (int)depth;
    encoder.options = (int)options;
    encoder.stream = stream;

    // Allocate output buffer to smallest size, so we remove checks if buffer was allocated in simdjson_encode_zval method
    smart_str_erealloc(&buf, 200);
    if (simdjson_encode_zval(&buf, parameter, &encoder) == SUCCESS) {
        if (options & SIMDJSON_APPEND_NEWLINE) {
            simdjson_smart_str_appendc(&buf, '\n');
        }

        simdjson_encode_write_stream(&buf, &encoder); // write rest
    }
    efree(buf.s);

    if (UNEXPECTED(encoder.error_code != SIMDJSON_ERROR_NONE)) {
        zend_throw_exception(simdjson_encoder_exception_ce, simdjson_get_error_msg(encoder.error_code), encoder.error_code);
        RETURN_THROWS();
    }

    RETURN_TRUE;
}

PHP_METHOD(SimdJsonBase64Encode, __construct) {
    zend_string *binary_string = NULL;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STR(binary_string)
    ZEND_PARSE_PARAMETERS_END();

    return_value = ZEND_THIS;
    ZVAL_STR_COPY(OBJ_PROP_NUM(Z_OBJ_P(ZEND_THIS), 0), binary_string);
}

PHP_METHOD(SimdJsonBase64Encode, jsonSerialize) {
    ZEND_PARSE_PARAMETERS_NONE();

    zend_string *binary_string = Z_STR(Z_OBJ_P(ZEND_THIS)->properties_table[0]);

    size_t encoded_length = simdutf::base64_length_from_binary(ZSTR_LEN(binary_string));
    zend_string *result = zend_string_alloc(encoded_length, 0);
    simdutf::binary_to_base64(ZSTR_VAL(binary_string), ZSTR_LEN(binary_string), ZSTR_VAL(result));
    ZSTR_VAL(result)[encoded_length] = '\0';
    GC_ADD_FLAGS(result, IS_STR_VALID_UTF8); // base64 encoded string must be always valid UTF-8 string

    RETURN_NEW_STR(result);
}

/** {{{ PHP_GINIT_FUNCTION
*/
PHP_GINIT_FUNCTION (simdjson) {
#if defined(COMPILE_DL_SIMDJSON) && defined(ZTS)
ZEND_TSRMLS_CACHE_UPDATE();
#endif
}
/* }}} */

/** {{{ PHP_MINIT_FUNCTION
*/
PHP_MINIT_FUNCTION (simdjson) {
#if PHP_VERSION_ID >= 80200
    // Interned string for empty array
    simdjson_json_empty_array = zend_new_interned_string(zend_string_init("[]", 2, 1));
    GC_ADD_FLAGS(simdjson_json_empty_array, IS_STR_VALID_UTF8);
#endif

    auto simdjson_exception_ce = register_class_SimdJsonException(spl_ce_RuntimeException);
	simdjson_decoder_exception_ce = register_class_SimdJsonDecoderException(simdjson_exception_ce);
	simdjson_encoder_exception_ce = register_class_SimdJsonEncoderException(simdjson_exception_ce);

	simdjson_base64_encode_ce = register_class_SimdJsonBase64Encode(php_json_serializable_ce);

    register_simdjson_symbols(0);

    return SUCCESS;
}
/* }}} */

/** {{{ PHP_MSHUTDOWN_FUNCTION
*/
PHP_MSHUTDOWN_FUNCTION (simdjson) {
    return SUCCESS;
}
/* }}} */

/** {{{ PHP_RINIT_FUNCTION
*/
PHP_RINIT_FUNCTION (simdjson) {
    SIMDJSON_G(parser) = NULL;
    return SUCCESS;
}
/* }}} */

/** {{{ PHP_RSHUTDOWN_FUNCTION
*/
PHP_RSHUTDOWN_FUNCTION (simdjson) {
    simdjson_php_parser *parser = SIMDJSON_G(parser);
    if (parser != NULL) {
        php_simdjson_free_parser(parser);
        SIMDJSON_G(parser) = NULL;
    }
    return SUCCESS;
}
/* }}} */

/** {{{ PHP_MINFO_FUNCTION
*/
PHP_MINFO_FUNCTION (simdjson) {
    php_info_print_table_start();

    php_info_print_table_row(2, "simdjson support", "enabled");
    php_info_print_table_row(2, "Version", PHP_SIMDJSON_VERSION);
    php_info_print_table_row(2, "Support", SIMDJSON_SUPPORT_URL);
    php_info_print_table_row(2, "simdjson library version", SIMDJSON_VERSION);
    php_info_print_table_row(2, "simdutf library version", SIMDUTF_VERSION);
    php_info_print_table_row(2, "Decoder implementation", simdjson::get_active_implementation()->description().c_str());
    php_info_print_table_row(2, "Encoder implementation", simdjson_encode_implementation());

    php_info_print_table_end();
}
/* }}} */

/** {{{ module depends
 */
zend_module_dep simdjson_deps[] = {
    {NULL, NULL, NULL}
};
/* }}} */

/** {{{ simdjson_module_entry
*/
zend_module_entry simdjson_module_entry = {
    STANDARD_MODULE_HEADER_EX, NULL,
    simdjson_deps,
    "simdjson",
    ext_functions,
    PHP_MINIT(simdjson),
    PHP_MSHUTDOWN(simdjson),
    PHP_RINIT(simdjson),
    PHP_RSHUTDOWN(simdjson),
    PHP_MINFO(simdjson),
    PHP_SIMDJSON_VERSION,
    PHP_MODULE_GLOBALS(simdjson),
    PHP_GINIT(simdjson),
    NULL,
    NULL,
    STANDARD_MODULE_PROPERTIES_EX
};
/* }}} */

/** {{{ DL support
 */
#ifdef COMPILE_DL_SIMDJSON
#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE();
#endif

ZEND_GET_MODULE(simdjson)
#endif
/* }}} */
