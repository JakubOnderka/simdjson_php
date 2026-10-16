--TEST--
simdjson_decode_iterate default batch_size matches simdjson's own default (1,000,000 bytes);
a single document larger than that requires an explicit, larger $batch_size
--FILE--
<?php
$big = json_encode(['data' => str_repeat('x', 2_000_000)]);

try {
    foreach (simdjson_decode_iterate($big) as $value) {
        echo "no exception thrown\n";
    }
} catch (\RuntimeException $e) {
    echo get_class($e), ': ', $e->getMessage(), "\n";
}

foreach (simdjson_decode_iterate($big, false, 512, strlen($big) + 1) as $value) {
    var_dump(strlen($value->data));
}

?>
--EXPECT--
SimdJsonDecoderException: This parser can't support a document that big
int(2000000)
