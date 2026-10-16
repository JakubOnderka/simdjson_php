--TEST--
simdjson_decode_iterate rejects invalid depth argument
--FILE--
<?php
foreach ([0, PHP_INT_MIN, PHP_INT_MAX] as $depth) {
    try {
        simdjson_decode_iterate('[]', true, $depth);
        echo "no exception thrown\n";
    } catch (\ValueError $e) {
        echo $e->getMessage(), "\n";
    }
}

?>
--EXPECTF--
simdjson_decode_iterate(): Argument #3 ($depth) must be greater than zero
simdjson_decode_iterate(): Argument #3 ($depth) must be greater than zero
simdjson_decode_iterate(): Argument #3 ($depth) exceeds maximum allowed value of %d
