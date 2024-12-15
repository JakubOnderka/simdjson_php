<?php

/** @generate-class-entries */

/**
 * @var int
 * @cvalue SIMDJSON_PRETTY_PRINT
 */
const SIMDJSON_PRETTY_PRINT = UNKNOWN;

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

/** @alias simdjson_validate */
function simdjson_is_valid(string $json, int $depth = 512): bool {}

function simdjson_decode(string $json, bool $associative = false, int $depth = 512): mixed {}

function simdjson_key_value(string $json, string $key, bool $associative = false, int $depth = 512): mixed {}

function simdjson_key_count(string $json, string $key, int $depth = 512, bool $throw_if_uncountable = false): int {}

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

/**
 * Thrown for error conditions on fields such as $depth that are not expected to be
 * from user-provided JSON, with similar behavior to php 8.0.
 *
 * NOTE: https://www.php.net/valueerror was added in php 8.0.
 * In older php versions, this extends Error instead.
 *
 * When support for php 8.0 is dropped completely,
 * a major release of simdjson will likely switch to a standard ValueError.
 */
class SimdJsonValueError extends ValueError {
}
