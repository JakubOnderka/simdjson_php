#ifndef SIMDJSON_ENCODER_H
#define SIMDJSON_ENCODER_H

#include "php.h"
#include "zend_smart_str.h"

/* error codes */
typedef enum {
    SIMDJSON_ERROR_NONE = 0,
    SIMDJSON_ERROR_DEPTH,
    SIMDJSON_ERROR_STATE_MISMATCH,
    SIMDJSON_ERROR_CTRL_CHAR,
    SIMDJSON_ERROR_SYNTAX,
    SIMDJSON_ERROR_UTF8,
    SIMDJSON_ERROR_RECURSION,
    SIMDJSON_ERROR_INF_OR_NAN,
    SIMDJSON_ERROR_UNSUPPORTED_TYPE,
    SIMDJSON_ERROR_INVALID_PROPERTY_NAME,
    SIMDJSON_ERROR_UTF16,
    SIMDJSON_ERROR_NON_BACKED_ENUM,
    SIMDJSON_ERROR_STREAM_WRITE,
} simdjson_error_code;

/* simdjson_encode() options */
#define SIMDJSON_PRETTY_PRINT               (1<<7)

typedef struct _simdjson_encoder simdjson_encoder;

struct _simdjson_encoder {
    int depth;
    int max_depth;
    simdjson_error_code error_code;
    php_stream *stream;
};

static const char* control_chars[] = {
    "\\u0000", "\\u0001", "\\u0002", "\\u0003", "\\u0004", "\\u0005", "\\u0006",
    "\\u0007", "\\u0008", "\\t",     "\\n",     "\\u000b", "\\f",     "\\r",
    "\\u000e", "\\u000f", "\\u0010", "\\u0011", "\\u0012", "\\u0013", "\\u0014",
    "\\u0015", "\\u0016", "\\u0017", "\\u0018", "\\u0019", "\\u001a", "\\u001b",
    "\\u001c", "\\u001d", "\\u001e", "\\u001f"};

// Chars that needs to be escaped
const char need_escaping[] = {
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

zend_result simdjson_encode_zval(smart_str *buf, zval *val, int options, simdjson_encoder *encoder);

zend_result simdjson_escape_string(smart_str *buf, zend_string *str, simdjson_encoder *encoder);

zend_result simdjson_encode_write_stream(smart_str *buf, simdjson_encoder* encoder);

#endif //SIMDJSON_ENCODER_H
