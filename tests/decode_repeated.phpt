--TEST--
simdjson_decode repeated strings
--SKIPIF--
<?php
if (PHP_VERSION_ID < 80200) echo "skip deduplication is supported since PHP 8.2\n";
?>
--FILE--
<?php
$json = '[{"ahoj":"svete"},{"ahoj":"moravo"}]';

$value = \json_decode($json, true);
debug_zval_dump(array_key_first($value[0]));

$value = \simdjson_decode($json, true);
debug_zval_dump(array_key_first($value[0]));
--EXPECTF--
string(4) "ahoj" refcount(2)
string(4) "ahoj" refcount(3)