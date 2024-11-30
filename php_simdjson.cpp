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
#include "ext/standard/flock_compat.h"
#include "ext/spl/spl_exceptions.h"

#include "php_simdjson.h"

/**
 * Both the declaration and the definition of PHP_SIMDJSON_API variables, functions must be within an 'extern "C"' block for Windows
 */
PHP_SIMDJSON_API zend_class_entry *simdjson_exception_ce;

} /* end extern "C" */

/* C++ header file for simdjson_php helper methods/classes */
#include "src/simdjson_compatibility.h"
#include "src/simdjson_decoder_defs.h"
#include "src/simdjson_encoder.h"
/* Single header file from fork of simdjson C project (to imitate php's handling of infinity/overflowing integers in json_decode) */
#include "src/simdjson.h"

#include "simdjson_arginfo.h"

ZEND_DECLARE_MODULE_GLOBALS(simdjson);

#define SIMDJSON_G(v) ZEND_MODULE_GLOBALS_ACCESSOR(simdjson, v)
static simdjson_php_parser *simdjson_get_parser() {
    simdjson_php_parser *parser = SIMDJSON_G(parser);
    if (parser == NULL) {
        parser = php_simdjson_create_parser();
        SIMDJSON_G(parser) = parser;
        ZEND_ASSERT(parser != NULL);
    }
    return parser;
}

PHP_SIMDJSON_API struct simdjson_php_parser *php_simdjson_get_default_singleton_parser(void) {
    return simdjson_get_parser();
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

// Free memory allocated by parser if capacity is bigger than 100 MB
static void simdjson_parser_cleanup() {
    simdjson_php_parser *parser = SIMDJSON_G(parser);
    if (parser->parser.capacity() > 100 * 1024 * 1024) {
        php_simdjson_free_parser(parser);
        SIMDJSON_G(parser) = NULL;
    }
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
    simdjson_php_error_code error = php_simdjson_validate(simdjson_get_parser(), json, depth);
    simdjson_parser_cleanup();
    ZVAL_BOOL(return_value, !error);
}

// Decode simple and common JSON values without allocating and using simdjson parser
static zend_always_inline bool simdjson_simple_decode(zend_string *json, zval *return_value, bool associative) {
    // Empty object
    if (ZSTR_LEN(json) == 2 && ZSTR_VAL(json)[0] == '{' && ZSTR_VAL(json)[1] == '}') {
        if (associative) {
            RETVAL_EMPTY_ARRAY();
        } else {
            object_init(return_value);
        }
        return true;
    }

    // Empty array
    if (ZSTR_LEN(json) == 2 && ZSTR_VAL(json)[0] == '[' && ZSTR_VAL(json)[1] == ']') {
        RETVAL_EMPTY_ARRAY();
        return true;
    }

    if (zend_string_equals_cstr(json, "true", 4)) {
        RETVAL_TRUE;
        return true;
    } else if (zend_string_equals_cstr(json, "false", 5)) {
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

    if (simdjson_simple_decode(json, return_value, associative)) {
        return;
    }

    simdjson_php_error_code error = php_simdjson_parse(simdjson_get_parser(), json, return_value, associative, depth);
    simdjson_parser_cleanup();
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
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "SS|bl", &json, &key, &associative, &depth) == FAILURE) {
        RETURN_THROWS();
    }
    if (!simdjson_validate_depth(depth, 4)) {
        RETURN_THROWS();
    }
    simdjson_php_error_code error = php_simdjson_key_value(simdjson_get_parser(), ZSTR_VAL(json), ZSTR_LEN(json), ZSTR_VAL(key), return_value, associative, depth);
    simdjson_parser_cleanup();
    if (error) {
        php_simdjson_throw_jsonexception(error);
        RETURN_THROWS();
    }
}

PHP_FUNCTION(simdjson_key_count) {
    zend_string *json = NULL;
    zend_string *key = NULL;
    zend_long depth = SIMDJSON_PARSE_DEFAULT_DEPTH;
    bool throw_if_uncountable = false;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "SS|lb", &json, &key, &depth, &throw_if_uncountable) == FAILURE) {
        RETURN_THROWS();
    }
    if (!simdjson_validate_depth(depth, 3)) {
        RETURN_THROWS();
    }
    simdjson_php_error_code error = php_simdjson_key_count(simdjson_get_parser(), ZSTR_VAL(json), ZSTR_LEN(json), ZSTR_VAL(key), return_value, depth, throw_if_uncountable);
    simdjson_parser_cleanup();
    if (error) {
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
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "SS|l", &json, &key, &depth) == FAILURE) {
        RETURN_THROWS();
    }
    if (!simdjson_validate_depth(depth, 3)) {
        RETURN_THROWS();
    }
    simdjson_php_error_code error = php_simdjson_key_exists(simdjson_get_parser(), ZSTR_VAL(json), ZSTR_LEN(json), ZSTR_VAL(key), depth);
    simdjson_parser_cleanup();
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

#ifdef IS_STR_VALID_UTF8
    // If string was already successfully validated, just return true
    if (ZSTR_IS_VALID_UTF8(string)) {
        RETURN_TRUE;
    }
#endif

    bool is_ok = simdjson::validate_utf8(ZSTR_VAL(string), ZSTR_LEN(string));
#ifdef IS_STR_VALID_UTF8
    if (EXPECTED(is_ok)) {
        // String is UTF-8 valid, so we can also set proper flag
        GC_ADD_FLAGS(string, IS_STR_VALID_UTF8);
    }
#endif
    RETURN_BOOL(is_ok);
}

static const char *php_json_get_error_msg(simdjson_error_code error_code)
{
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

PHP_FUNCTION(simdjson_encode)
{
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

    encoder.max_depth = (int)depth;
    // Allocate output buffer to smallest size, so we remove checks if buffer was allocated in simdjson_encode_zval method
    smart_str_erealloc(&buf, 200);
    simdjson_encode_zval(&buf, parameter, (int)options, &encoder);

    if (UNEXPECTED(encoder.error_code != SIMDJSON_ERROR_NONE)) {
        efree(buf.s);
        zend_throw_exception(simdjson_exception_ce, php_json_get_error_msg(encoder.error_code), encoder.error_code);
        RETURN_THROWS();
    }

    if (options & SIMDJSON_APPEND_NEWLINE) {
        smart_str_appendc(&buf, '\n');
    }

    RETURN_STR(smart_str_extract(&buf));
}

PHP_FUNCTION(simdjson_encode_to_stream)
{
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

    encoder.max_depth = (int)depth;
    encoder.stream = stream;

    if (options & SIMDJSON_LOCK_EX && php_stream_supports_lock(stream) && php_stream_lock(stream, LOCK_EX)) {
        php_error_docref(NULL, E_WARNING, "Could not lock stream for writing");
        RETURN_FALSE;
    }

    smart_str_erealloc(&buf, 1024 * 8);
    simdjson_encode_zval(&buf, parameter, (int)options, &encoder);

    if (options & SIMDJSON_APPEND_NEWLINE) {
        smart_str_appendc(&buf, '\n');
    }

    simdjson_encode_write_stream(&buf, &encoder); // write rest
    efree(buf.s);

    if (options & SIMDJSON_LOCK_EX && php_stream_supports_lock(stream) && php_stream_lock(stream, LOCK_UN)) {
        php_error_docref(NULL, E_WARNING, "Could not unlock stream");
        RETURN_FALSE;
    }

    if (UNEXPECTED(encoder.error_code != SIMDJSON_ERROR_NONE)) {
        zend_throw_exception(simdjson_exception_ce, php_json_get_error_msg(encoder.error_code), encoder.error_code);
        RETURN_THROWS();
    }

    RETURN_TRUE;
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
#define SIMDJSON_REGISTER_ERROR_CODE_CONSTANT(errcode) REGISTER_LONG_CONSTANT("SIMDJSON_ERR_" #errcode, simdjson::errcode, CONST_PERSISTENT | CONST_CS)
#define SIMDJSON_REGISTER_CUSTOM_ERROR_CODE_CONSTANT(errcode, val) REGISTER_LONG_CONSTANT("SIMDJSON_ERR_" #errcode, (val), CONST_PERSISTENT | CONST_CS)
PHP_MINIT_FUNCTION (simdjson) {
	simdjson_exception_ce = register_class_SimdJsonException(spl_ce_RuntimeException);

    SIMDJSON_REGISTER_ERROR_CODE_CONSTANT(CAPACITY);                   ///< This parser can't support a document that big
    // SIMDJSON_REGISTER_ERROR_CODE_CONSTANT(MEMALLOC);                   ///< Error allocating memory, most likely out of memory
    SIMDJSON_REGISTER_ERROR_CODE_CONSTANT(TAPE_ERROR);                 ///< Something went wrong, this is a generic error
    SIMDJSON_REGISTER_ERROR_CODE_CONSTANT(DEPTH_ERROR);                ///< Your document exceeds the user-specified depth limitation
    SIMDJSON_REGISTER_ERROR_CODE_CONSTANT(STRING_ERROR);               ///< Problem while parsing a string
    SIMDJSON_REGISTER_ERROR_CODE_CONSTANT(T_ATOM_ERROR);               ///< Problem while parsing an atom starting with the letter 't'
    SIMDJSON_REGISTER_ERROR_CODE_CONSTANT(F_ATOM_ERROR);               ///< Problem while parsing an atom starting with the letter 'f'
    SIMDJSON_REGISTER_ERROR_CODE_CONSTANT(N_ATOM_ERROR);               ///< Problem while parsing an atom starting with the letter 'n'
    SIMDJSON_REGISTER_ERROR_CODE_CONSTANT(NUMBER_ERROR);               ///< Problem while parsing a number
    SIMDJSON_REGISTER_ERROR_CODE_CONSTANT(UTF8_ERROR);                 ///< the input is not valid UTF-8
    SIMDJSON_REGISTER_ERROR_CODE_CONSTANT(UNINITIALIZED);              ///< unknown error, or uninitialized document
    SIMDJSON_REGISTER_ERROR_CODE_CONSTANT(EMPTY);                      ///< no structural element found
    SIMDJSON_REGISTER_ERROR_CODE_CONSTANT(UNESCAPED_CHARS);            ///< found unescaped characters in a string.
    SIMDJSON_REGISTER_ERROR_CODE_CONSTANT(UNCLOSED_STRING);            ///< missing quote at the end
    SIMDJSON_REGISTER_ERROR_CODE_CONSTANT(UNSUPPORTED_ARCHITECTURE);   ///< unsupported architecture
    SIMDJSON_REGISTER_ERROR_CODE_CONSTANT(INCORRECT_TYPE);             ///< JSON element has a different type than user expected
    SIMDJSON_REGISTER_ERROR_CODE_CONSTANT(NUMBER_OUT_OF_RANGE);        ///< JSON number does not fit in 64 bits
    SIMDJSON_REGISTER_ERROR_CODE_CONSTANT(INDEX_OUT_OF_BOUNDS);        ///< JSON array index too large
    SIMDJSON_REGISTER_ERROR_CODE_CONSTANT(NO_SUCH_FIELD);              ///< JSON field not found in object
    SIMDJSON_REGISTER_ERROR_CODE_CONSTANT(IO_ERROR);                   ///< Error reading a file
    SIMDJSON_REGISTER_ERROR_CODE_CONSTANT(INVALID_JSON_POINTER);       ///< Invalid JSON pointer reference
    SIMDJSON_REGISTER_ERROR_CODE_CONSTANT(INVALID_URI_FRAGMENT);       ///< Invalid URI fragment
    SIMDJSON_REGISTER_ERROR_CODE_CONSTANT(UNEXPECTED_ERROR);           ///< indicative of a bug in simdjson
    SIMDJSON_REGISTER_ERROR_CODE_CONSTANT(PARSER_IN_USE);              ///< parser is already in use.
    SIMDJSON_REGISTER_ERROR_CODE_CONSTANT(OUT_OF_ORDER_ITERATION);     ///< tried to iterate an array or object out of order
    SIMDJSON_REGISTER_ERROR_CODE_CONSTANT(INSUFFICIENT_PADDING);       ///< The JSON doesn't have enough padding for simdjson to safely parse it.
    SIMDJSON_REGISTER_ERROR_CODE_CONSTANT(INCOMPLETE_ARRAY_OR_OBJECT); ///< The document ends early.
    SIMDJSON_REGISTER_ERROR_CODE_CONSTANT(SCALAR_DOCUMENT_AS_VALUE);   ///< A scalar document is treated as a value.
    SIMDJSON_REGISTER_ERROR_CODE_CONSTANT(OUT_OF_BOUNDS);              ///< Attempted to access location outside of document.
    SIMDJSON_REGISTER_ERROR_CODE_CONSTANT(TRAILING_CONTENT);           ///< Unexpected trailing content in the JSON input
    SIMDJSON_REGISTER_CUSTOM_ERROR_CODE_CONSTANT(KEY_COUNT_NOT_COUNTABLE, SIMDJSON_PHP_ERR_KEY_COUNT_NOT_COUNTABLE); ///< JSON pointer refers to a value that cannot be counted
    SIMDJSON_REGISTER_CUSTOM_ERROR_CODE_CONSTANT(INVALID_PROPERTY, SIMDJSON_PHP_ERR_INVALID_PHP_PROPERTY); ///< Invalid property name

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
    php_info_print_table_header(2, "simdjson support", "enabled");

    php_info_print_table_row(2, "Version", PHP_SIMDJSON_VERSION);
    php_info_print_table_row(2, "Support", SIMDJSON_SUPPORT_URL);
    php_info_print_table_row(2, "Implementation", simdjson::get_active_implementation()->description().c_str());

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
