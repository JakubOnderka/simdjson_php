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
 * @cvalue SIMDJSON_LOCK_EX
 */
const SIMDJSON_LOCK_EX = UNKNOWN;

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

function simdjson_cleanup(): true {}

function simdjson_is_valid_utf8(string $string): bool {}

function simdjson_encode(mixed $value, int $flags = 0, int $depth = 512): string|false {}

function simdjson_encode_to_stream(mixed $value, resource $res, int $flags = 0, int $depth = 512) : bool {}

/**
 * This is used with php-src's build/gen_stubs.php to generate argument info compatible with php 7.0 and above.
 *
 * See README.md for function documentation.
 *
 */
class SimdJsonException extends RuntimeException {
}
