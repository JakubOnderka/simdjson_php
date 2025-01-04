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
#define SIMDJSON_APPEND_NEWLINE             (1<<12)
#define SIMDJSON_INVALID_UTF8_IGNORE        (1<<20)
#define SIMDJSON_INVALID_UTF8_SUBSTITUTE    (1<<21)

typedef struct _simdjson_encoder simdjson_encoder;

struct _simdjson_encoder {
    int depth;
    int max_depth;
    int options;
    simdjson_error_code error_code;
    php_stream *stream;
};

// max lenght of escaped string is 6 chars, but we coping 8 bytes is faster on 64 platforms
#define SIMDJSON_ENCODER_ESCAPE_LENGTH 8

typedef struct {
    const char str[SIMDJSON_ENCODER_ESCAPE_LENGTH];
    size_t len;
} _simdjson_escaped;

static const _simdjson_escaped simdjson_escape[] = {
    {"\\u0000", 6},
    {"\\u0001", 6},
    {"\\u0002", 6},
    {"\\u0003", 6},
    {"\\u0004", 6},
    {"\\u0005", 6},
    {"\\u0006", 6},
    {"\\u0007", 6},
    {"\\b", 2},
    {"\\t", 2},
    {"\\n", 2},
    {"\\u000b", 6},
    {"\\f", 2},
    {"\\r", 2},
    {"\\u000e", 6},
    {"\\u000f", 6},
    {"\\u0010", 6},
    {"\\u0011", 6},
    {"\\u0012", 6},
    {"\\u0013", 6},
    {"\\u0014", 6},
    {"\\u0015", 6},
    {"\\u0016", 6},
    {"\\u0017", 6},
    {"\\u0018", 6},
    {"\\u0019", 6},
    {"\\u001a", 6},
    {"\\u001b", 6},
    {"\\u001c", 6},
    {"\\u001d", 6},
    {"\\u001e", 6},
    {"\\u001f", 6},
    {"", 0},
    {"", 0},
    {"\\\"", 2}, // 34
    {"", 0},
    {"", 0},
    {"", 0},
    {"", 0},
    {"", 0},
    {"", 0},
    {"", 0},
    {"", 0},
    {"", 0},
    {"", 0}, // 44
    {"", 0},
    {"", 0},
    {"", 0},
    {"", 0},
    {"", 0},
    {"", 0},
    {"", 0},
    {"", 0},
    {"", 0},
    {"", 0}, // 54
    {"", 0},
    {"", 0},
    {"", 0},
    {"", 0},
    {"", 0},
    {"", 0},
    {"", 0},
    {"", 0},
    {"", 0},
    {"", 0}, // 64
    {"", 0},
    {"", 0},
    {"", 0},
    {"", 0},
    {"", 0},
    {"", 0},
    {"", 0},
    {"", 0},
    {"", 0},
    {"", 0}, // 74
    {"", 0},
    {"", 0},
    {"", 0},
    {"", 0},
    {"", 0},
    {"", 0},
    {"", 0},
    {"", 0},
    {"", 0},
    {"", 0}, // 84
    {"", 0},
    {"", 0},
    {"", 0},
    {"", 0},
    {"", 0},
    {"", 0},
    {"", 0},
    {"\\\\", 2}, // 92
};

// Chars that needs to be escaped according to RFC specification
static const char simdjson_need_escaping[] = {
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 32
    0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 64
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, // 96
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 128
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 160
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 192
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 224
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 256
};

zend_result simdjson_encode_zval(smart_str *buf, zval *val, simdjson_encoder *encoder);

static zend_result simdjson_escape_string(smart_str *buf, zend_string *str, simdjson_encoder *encoder);

zend_result simdjson_encode_write_stream(smart_str *buf, simdjson_encoder* encoder);

const char* simdjson_encode_implementation();

#endif //SIMDJSON_ENCODER_H
