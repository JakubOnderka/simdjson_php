<?php

/** @generate-class-entries */

/**
 * @var int
 * @cvalue SIMDJSON_PRETTY_PRINT
 */
const SIMDJSON_PRETTY_PRINT = UNKNOWN;
/**
 * @var int
 * @cvalue SIMDJSON_APPEND_NEWLINE
 */
const SIMDJSON_APPEND_NEWLINE = UNKNOWN;
/**
 * @var int
 * @cvalue SIMDJSON_INVALID_UTF8_IGNORE
 */
const SIMDJSON_INVALID_UTF8_IGNORE = UNKNOWN;
/**
 * @var int
 * @cvalue SIMDJSON_INVALID_UTF8_SUBSTITUTE
 */
const SIMDJSON_INVALID_UTF8_SUBSTITUTE = UNKNOWN;

// Encoder errors
/**
 * @var int
 * @cvalue SIMDJSON_ERROR_NONE
 */
const SIMDJSON_ERROR_NONE = UNKNOWN;
/**
 * @var int
 * @cvalue SIMDJSON_ERROR_DEPTH
 */
const SIMDJSON_ERROR_DEPTH = UNKNOWN;
/**
 * @var int
 * @cvalue SIMDJSON_ERROR_UTF8
 */
const SIMDJSON_ERROR_UTF8 = UNKNOWN;
/**
 * @var int
 * @cvalue SIMDJSON_ERROR_RECURSION
 */
const SIMDJSON_ERROR_RECURSION = UNKNOWN;
/**
 * @var int
 * @cvalue SIMDJSON_ERROR_INF_OR_NAN
 */
const SIMDJSON_ERROR_INF_OR_NAN = UNKNOWN;
/**
 * @var int
 * @cvalue SIMDJSON_ERROR_UNSUPPORTED_TYPE
 */
const SIMDJSON_ERROR_UNSUPPORTED_TYPE = UNKNOWN;
/**
 * @var int
 * @cvalue SIMDJSON_ERROR_INVALID_PROPERTY_NAME
 */
const SIMDJSON_ERROR_INVALID_PROPERTY_NAME = UNKNOWN;
/**
 * @var int
 * @cvalue SIMDJSON_ERROR_NON_BACKED_ENUM
 */
const SIMDJSON_ERROR_NON_BACKED_ENUM = UNKNOWN;

// Decoder errors
/**
 * @var int
 * @cvalue simdjson::CAPACITY
 */
const SIMDJSON_ERR_CAPACITY = UNKNOWN;
/**
 * @var int
 * @cvalue simdjson::TAPE_ERROR
 */
const SIMDJSON_ERR_TAPE_ERROR = UNKNOWN;
/**
 * @var int
 * @cvalue simdjson::DEPTH_ERROR
 */
const SIMDJSON_ERR_DEPTH_ERROR = UNKNOWN;
/**
 * @var int
 * @cvalue simdjson::STRING_ERROR
 */
const SIMDJSON_ERR_STRING_ERROR = UNKNOWN;
/**
 * @var int
 * @cvalue simdjson::T_ATOM_ERROR
 */
const SIMDJSON_ERR_T_ATOM_ERROR = UNKNOWN;
/**
 * @var int
 * @cvalue simdjson::F_ATOM_ERROR
 */
const SIMDJSON_ERR_F_ATOM_ERROR = UNKNOWN;
/**
 * @var int
 * @cvalue simdjson::N_ATOM_ERROR
 */
const SIMDJSON_ERR_N_ATOM_ERROR = UNKNOWN;
/**
 * @var int
 * @cvalue simdjson::NUMBER_ERROR
 */
const SIMDJSON_ERR_NUMBER_ERROR = UNKNOWN;
/**
 * @var int
 * @cvalue simdjson::UTF8_ERROR
 */
const SIMDJSON_ERR_UTF8_ERROR = UNKNOWN;
/**
 * @var int
 * @cvalue simdjson::UNINITIALIZED
 */
const SIMDJSON_ERR_UNINITIALIZED = UNKNOWN;
/**
 * @var int
 * @cvalue simdjson::EMPTY
 */
const SIMDJSON_ERR_EMPTY = UNKNOWN;
/**
 * @var int
 * @cvalue simdjson::UNESCAPED_CHARS
 */
const SIMDJSON_ERR_UNESCAPED_CHARS = UNKNOWN;
/**
 * @var int
 * @cvalue simdjson::UNCLOSED_STRING
 */
const SIMDJSON_ERR_UNCLOSED_STRING = UNKNOWN;
/**
 * @var int
 * @cvalue simdjson::UNSUPPORTED_ARCHITECTURE
 */
const SIMDJSON_ERR_UNSUPPORTED_ARCHITECTURE = UNKNOWN;
/**
 * @var int
 * @cvalue simdjson::INCORRECT_TYPE
 */
const SIMDJSON_ERR_INCORRECT_TYPE = UNKNOWN;
/**
 * @var int
 * @cvalue simdjson::NUMBER_OUT_OF_RANGE
 */
const SIMDJSON_ERR_NUMBER_OUT_OF_RANGE = UNKNOWN;
/**
 * @var int
 * @cvalue simdjson::INDEX_OUT_OF_BOUNDS
 */
const SIMDJSON_ERR_INDEX_OUT_OF_BOUNDS = UNKNOWN;
/**
 * @var int
 * @cvalue simdjson::NO_SUCH_FIELD
 */
const SIMDJSON_ERR_NO_SUCH_FIELD = UNKNOWN;
/**
 * @var int
 * @cvalue simdjson::IO_ERROR
 */
const SIMDJSON_ERR_IO_ERROR = UNKNOWN;
/**
 * @var int
 * @cvalue simdjson::INVALID_JSON_POINTER
 */
const SIMDJSON_ERR_INVALID_JSON_POINTER = UNKNOWN;
/**
 * @var int
 * @cvalue simdjson::INVALID_URI_FRAGMENT
 */
const SIMDJSON_ERR_INVALID_URI_FRAGMENT = UNKNOWN;
/**
 * @var int
 * @cvalue simdjson::UNEXPECTED_ERROR
 */
const SIMDJSON_ERR_UNEXPECTED_ERROR = UNKNOWN;
/**
 * @var int
 * @cvalue simdjson::PARSER_IN_USE
 */
const SIMDJSON_ERR_PARSER_IN_USE = UNKNOWN;
/**
 * @var int
 * @cvalue simdjson::OUT_OF_ORDER_ITERATION
 */
const SIMDJSON_ERR_OUT_OF_ORDER_ITERATION = UNKNOWN;
/**
 * @var int
 * @cvalue simdjson::INSUFFICIENT_PADDING
 */
const SIMDJSON_ERR_INSUFFICIENT_PADDING = UNKNOWN;
/**
 * @var int
 * @cvalue simdjson::INCOMPLETE_ARRAY_OR_OBJECT
 */
const SIMDJSON_ERR_INCOMPLETE_ARRAY_OR_OBJECT = UNKNOWN;
/**
 * @var int
 * @cvalue simdjson::SCALAR_DOCUMENT_AS_VALUE
 */
const SIMDJSON_ERR_SCALAR_DOCUMENT_AS_VALUE = UNKNOWN;
/**
 * @var int
 * @cvalue simdjson::OUT_OF_BOUNDS
 */
const SIMDJSON_ERR_OUT_OF_BOUNDS = UNKNOWN;
/**
 * @var int
 * @cvalue simdjson::TRAILING_CONTENT
 */
const SIMDJSON_ERR_TRAILING_CONTENT = UNKNOWN;
/**
 * @var int
 * @cvalue SIMDJSON_PHP_ERR_KEY_COUNT_NOT_COUNTABLE
 */
const SIMDJSON_ERR_KEY_COUNT_NOT_COUNTABLE = UNKNOWN;
/**
 * @var int
 * @cvalue SIMDJSON_PHP_ERR_INVALID_PHP_PROPERTY
 */
const SIMDJSON_ERR_INVALID_PROPERTY = UNKNOWN;

function simdjson_validate(string $json, int $depth = 512): bool {}

/**
 * Returns true if json is valid.
 *
 * @param string $json The JSON string being decoded
 * @param int $depth the maximum nesting depth of the structure being decoded.
 * @return bool
 * @throws ValueError for invalid $depth
 * @alias simdjson_validate
 */
function simdjson_is_valid(string $json, int $depth = 512): bool {}

/**
 * Takes a JSON encoded string and converts it into a PHP variable.
 * Similar to json_decode()
 *
 * @param string $json The JSON string being decoded
 * @param bool $associative When true, JSON objects will be returned as associative arrays.
 *                          When false, JSON objects will be returned as objects.
 * @param int $depth the maximum nesting depth of the structure being decoded.
 * @return array|stdClass|string|float|int|bool|null
 * @throws SimdJsonException for invalid JSON
 *                           (or $json over 4GB long, or out of range integer/float)
 * @throws ValueError for invalid $depth
 */
function simdjson_decode(string $json, bool $associative = false, int $depth = 512): mixed {}

/**
 * Takes a JSON encoded string and converts it into a PHP variable.
 * Similar to json_decode()
 *
 * @param resource $res A file system pointer resource that is typically created using fopen().
 * @param bool $associative When true, JSON objects will be returned as associative arrays.
 *                          When false, JSON objects will be returned as objects.
 * @param int $depth the maximum nesting depth of the structure being decoded.
 * @return array|stdClass|string|float|int|bool|null
 * @throws SimdJsonException for invalid JSON
 *                           (or $json over 4GB long, or out of range integer/float)
 * @throws ValueError for invalid $depth
 */
function simdjson_decode_from_stream($res, bool $associative = false, int $depth = 512): mixed {}

/**
 * Returns the value at the json pointer $key
 *
 * @param string $json The JSON string being decoded
 * @param string $key The JSON pointer being requested
 * @param int $depth the maximum nesting depth of the structure being decoded.
 * @param bool $associative When true, JSON objects will be returned as associative arrays.
 *                          When false, JSON objects will be returned as objects.
 * @return array|stdClass|string|float|int|bool|null the value at $key
 * @throws SimdJsonException for invalid JSON or invalid JSON pointer
 *                           (or document over 4GB, or out of range integer/float)
 * @throws ValueError for invalid $depth
 * @see https://www.rfc-editor.org/rfc/rfc6901.html
 */
function simdjson_key_value(string $json, string $key, bool $associative = false, int $depth = 512): mixed {}

/**
 * Parses $json and returns the number of keys in $json matching the JSON pointer $key
 *
 * @param string $json The JSON string being decoded
 * @param string $key The JSON pointer being requested
 * @param int $depth The maximum nesting depth of the structure being decoded.
 * @param bool $throw_if_uncountable If true, then throw SimdJsonException instead of
 *                                   returning 0 for JSON pointers
 *                                   to values that are neither objects nor arrays.
 * @return int
 * @throws SimdJsonException for invalid JSON or invalid JSON pointer
 *                           (or document over 4GB, or out of range integer/float)
 * @throws ValueError for invalid $depth
 * @see https://www.rfc-editor.org/rfc/rfc6901.html
 */
function simdjson_key_count(string $json, string $key, int $depth = 512, bool $throw_if_uncountable = false): int {}

/**
 * Returns true if the JSON pointer $key could be found.
 *
 * @param string $json The JSON string being decoded
 * @param string $key The JSON pointer being requested
 * @param int $depth the maximum nesting depth of the structure being decoded.
 * @return bool (false if key is not found)
 * @throws SimdJsonException for invalid JSON or invalid JSON pointer
 *                           (or document over 4GB, or out of range integer/float)
 * @throws ValueError for invalid $depth
 * @see https://www.rfc-editor.org/rfc/rfc6901.html
 */
function simdjson_key_exists(string $json, string $key, int $depth = 512): bool {}

/**
 * Release memory allocated by simdjson parser
 */
function simdjson_cleanup(): true {}

/**
 * Check is string is valid UTF-8 encoded string
 *
 * @param string $string
 * @return bool
 */
function simdjson_is_valid_utf8(string $string): bool {}

/**
 * Returns the JSON representation of a value
 *
 * @param mixed $value The value being encoded. Can be any type except a resource.
 * @param int $flags Bitmask consisting of SIMDJSON_PRETTY_PRINT or SIMDJSON_APPEND_NEWLINE.
 * @param int $depth Set the maximum depth. Must be greater than zero.
 * @return string
 */
function simdjson_encode(mixed $value, int $flags = 0, int $depth = 512): string {}

/**
 * Writes the JSON representation of a value to given stream
 *
  * @param mixed $value The value being encoded. Can be any type except a resource.
  * @param resource $res A file system pointer resource that is typically created using fopen().
  * @param int $flags Bitmask consisting of SIMDJSON_PRETTY_PRINT, SIMDJSON_APPEND_NEWLINE or SIMDJSON_INVALID_UTF8_SUBSTITUTE.
  * @param int $depth Set the maximum depth. Must be greater than zero.
  * @return bool
 */
function simdjson_encode_to_stream(mixed $value, $res, int $flags = 0, int $depth = 512) : true {}

class SimdJsonException extends RuntimeException {
}

/**
 * Optimised converting base64 encoded string to JSON
 * When converting base64 encoded string JSON, we can avoid all checks – that string is valid unicode and that sting need
 * to be escaped.
 * @strict-properties
 */
final class SimdJsonBase64Encode implements JsonSerializable {
    private string $string;

    /**
     * @param string $string The data to encode.
     */
    public function __construct(string $string) {}

    /**
     * @return mixed Base64 encoded string
     */
    public function jsonSerialize(): mixed {}

    /**
     * @return string Base64 encoded string
     * @alias SimdJsonBase64Encode::jsonSerialize
     */
    public function __toString(): string {}
}
