--TEST--
simdjson_decode_iterate throws an exception when the JSON is invalid
--FILE--
<?php
$it = simdjson_decode_iterate('{invalid}');

try {
    foreach ($it as $value) {
        var_dump($value);
    }
    echo "no exception thrown\n";
} catch (\RuntimeException $e) {
    echo get_class($e), ': ', $e->getMessage(), "\n";
}

// Once an error occurred, the iterator is considered finished.
var_dump($it->valid());

?>
--EXPECT--
SimdJsonDecoderException: The JSON document has an improper structure: missing or superfluous commas, braces, missing keys, etc.
bool(false)
