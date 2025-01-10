--TEST--
simdjson_decode repeated strings between calls
--SKIPIF--
<?php
if (PHP_VERSION_ID < 80200) echo "skip deduplication is supported since PHP 8.2\n";
?>
--FILE--
<?php
$json = '[{"ahoj":"svete"}]';

$value1 = \simdjson_decode($json, true);
debug_zval_dump(array_key_first($value1[0]));

$value2 = \simdjson_decode($json, true);
debug_zval_dump(array_key_first($value2[0]));

simdjson_cleanup(); // removes also allocated strings

debug_zval_dump(array_key_first($value1[0]));

--EXPECT--
string(4) "ahoj" refcount(3)
string(4) "ahoj" refcount(4)
string(4) "ahoj" refcount(3)
