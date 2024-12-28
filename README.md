# simdjson_php

🚀 Super fast JSON encoding and decoding for PHP that utilise [simdjson project](https://github.com/lemire/simdjson). 

*This is a fork of [crazyxman/simdjson_php](https://github.com/crazyxman/simdjson_php) with new optimisations and encoding support.*

[![Build Status](https://github.com/JakubOnderka/simdjson_php/actions/workflows/integration.yml/badge.svg?branch=master)](https://github.com/JakubOnderka/simdjson_php/actions/workflows/integration.yml?query=branch%3Amaster)

## How fast is simdjson_php?

* Decoding is 3x faster compared to PHP's `json_decode()`
* Encoding is 2.5x faster compared to PHP's `json_encode()`
* Validation is 6x faster compared to PHP's `json_validate()`

| Method              | Original | simdjson_php | Speedup  |
|---------------------|----------|--------------|----------| 
| Decode to array     | 1.48 ms  | 0.51 ms      | **2.9x** |
| Decode to object    | 1.59 ms  | 0.71 ms      | **2.2x** |
| Encode              | 0.67 ms  | 0.26 ms      | **2.5x** |
| Encode pretty print | 0.83 ms  | 0.31 ms      | **2.6x** |
| Validate            | 1.37 ms  | 0.22 ms      | **6.2x** |

## Requirement

- PHP 8.0+ (PHP 8.2+ recommended for maximum performance)
- Prerequisites: g++ (version 7 or better) or clang++ (version 6 or better), and a 64-bit system with a command-line shell (e.g., Linux, macOS, FreeBSD).

## Compile simdjson_php in Linux
```
$ phpize
$ ./configure
$ make
$ make test
$ make install
```

Add the following line to your php.ini

```
extension=simdjson.so
```

## Usage
```php
$jsonString = <<<'JSON'
{
  "Image": {
    "Width":  800,
    "Height": 600,
    "Title":  "View from 15th Floor",
    "Thumbnail": {
      "Url":    "http://www.example.com/image/481989943",
      "Height": 125,
      "Width":  100
    },
    "Animated" : false,
    "IDs": [116, 943, 234, 38793, {"p": "30"}]
  }
}
JSON;

// Check if a JSON string is valid:
$isValid = simdjson_validate($jsonString); //return bool
var_dump($isValid);  // true

// Parsing a JSON string. similar to the json_decode() function but without the fourth argument
try {
    // returns array|stdClass|string|float|int|bool|null.
    $parsedJSON = simdjson_decode($jsonString, true, 512);
    var_dump($parsedJSON); // PHP array
} catch (RuntimeException $e) {
    echo "Failed to parse $jsonString: {$e->getMessage()}\n";
}

// Encode to JSON string
var_dump(simdjson_encode($parsedJSON));

// note. "/" is a separator. Can be used as the "key" of the object and the "index" of the array
// E.g. "/Image/Thumbnail/Url" is recommended starting in simdjson 4.0.0,
// but "Image/Thumbnail/Url" is accepted for now.

// get the value of a "key" in a json string
// (before simdjson 4.0.0, the recommended leading "/" had to be omitted)
$value = simdjson_key_value($jsonString, "/Image/Thumbnail/Url");
var_dump($value); // string(38) "http://www.example.com/image/481989943"

$value = simdjson_key_value($jsonString, "/Image/IDs/4", true);
var_dump($value);
/*
array(1) {
  ["p"]=>
  string(2) "30"
}
*/

// check if the key exists. return true|false|null. "true" exists, "false" does not exist,
// throws for invalid JSON.
$res = simdjson_key_exists($jsonString, "/Image/IDs/1");
var_dump($res) //bool(true)

// count the values
$res = simdjson_key_count($jsonString, "/Image/IDs");
var_dump($res) //int(5)
```

## Encoder

Most of available options of default `json_encode()` method are not supported by `simdjson_encode()` as they are usually useless. The only supported option from `json_encode()` is `SIMDJSON_PRETTY_PRINT`.

`simdjson_encode($value)` method has very similar behaviour as `json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR)`

Differences are:
* uses different algorithm to convert floating-point number to string
* even when `JSON_UNESCAPED_UNICODE` is enabled, PHP `json_encode()` escapes some Unicode chars that do not need to be escaped. `simdjson_encode()` escape just Unicode chars that needs to be escaped by JSON spec.
* new option `SIMDJSON_APPEND_NEWLINE` will append new line character (`\n`) to end of encoded string
* `simdjson_encode_to_stream()` method allows you to write encoded string directly to PHP stream

## Decoder edge cases

There are some differences from `json_decode()` due to the implementation of the underlying simdjson library. This will throw a RuntimeException if simdjson rejects the JSON.

Note that the simdjson PECL is using a fork of the simdjson C library to imitate php's handling of integers and floats in JSON.

1) The maximum string length that can be passed to `simdjson_decode()` is 4GiB (4294967295 bytes).
   `json_decode()` can decode longer strings.

2) The handling of max depth is counted slightly differently for empty vs non-empty objects/arrays.
   In `json_decode`, an array with a scalar has the same depth as an array with no elements.
   In `simdjson_decode`, an array with a scalar is one level deeper than an array with no elements.
   For typical use cases, this shouldn't matter.
   (e.g. `simdjson_decode('[[]]', true, 2)` will succeed but `json_decode('[[]]', true, 2)` and `simdjson_decode('[[1]]', true, 2)` will fail.)

## Benchmarks
See the [benchmark](./benchmark) folder for more benchmarks.
