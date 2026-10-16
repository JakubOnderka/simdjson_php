--TEST--
simdjson_decode_iterate reject documents nested deeper than the depth limit
--FILE--
<?php
try {
    foreach (simdjson_decode_iterate('[[[[1]]]]', false, 2) as $value) {
        var_dump($value);
    }
    echo "no exception thrown\n";
} catch (\RuntimeException $e) {
    echo get_class($e), ': ', $e->getMessage(), "\n";
}

?>
--EXPECT--
SimdJsonDecoderException: The JSON document was too deep (too many nested objects and arrays)
