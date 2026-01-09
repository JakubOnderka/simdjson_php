--TEST--
simdjson_decode repeated key deduplication limit
--SKIPIF--
<?php
if (PHP_VERSION_ID < 80200) echo "skip deduplication is supported since PHP 8.2\n";
?>
--FILE--
<?php
$array = [];
for ($i = 0; $i < 300; $i++) {
    $array[] = ["key$i" => $i];
}

$encoded = simdjson_encode($array);
$decoded = simdjson_decode($encoded, true);
debug_zval_dump(array_key_first($decoded[0]));
debug_zval_dump(array_key_first($decoded[299]));

$array = [];
for ($i = 0; $i < 300; $i++) {
    $array[] = ["key_new_$i" => $i];
}

$encoded = simdjson_encode($array);
$decoded = simdjson_decode($encoded, true);
debug_zval_dump(array_key_first($decoded[0]));
debug_zval_dump(array_key_first($decoded[299]));

--EXPECT--
string(4) "key0" refcount(3)
string(6) "key299" refcount(2)
string(9) "key_new_0" refcount(3)
string(11) "key_new_299" refcount(2)
