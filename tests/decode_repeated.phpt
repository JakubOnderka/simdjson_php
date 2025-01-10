--TEST--
simdjson_decode repeated strings
--SKIPIF--
<?php
if (PHP_VERSION_ID < 80200) echo "skip deduplication is supported since PHP 8.2\n";
?>
--FILE--
<?php
$json = '[{"ahoj":"svete"},{"ahoj":"moravo"},{"very_long_key_that_will_not_be_deduplicated_by_simdjson_extension":true},{"very_long_key_that_will_not_be_deduplicated_by_simdjson_extension":true}]';

$value = \json_decode($json, true);
debug_zval_dump(array_key_first($value[0]));

$value = \simdjson_decode($json, true);
debug_zval_dump(array_key_first($value[0]));

$value = \json_decode($json, false);
debug_zval_dump(@key($value[0]));

$value = \simdjson_decode($json, false);
debug_zval_dump(@key($value[0]));

$value = \json_decode($json, true);
debug_zval_dump(array_key_first($value[2]));

$value = \simdjson_decode($json, true);
debug_zval_dump(array_key_first($value[2]));

$value = \json_decode($json, false);
debug_zval_dump(@key($value[2]));

$value = \simdjson_decode($json, false);
debug_zval_dump(@key($value[2]));
--EXPECT--
string(4) "ahoj" refcount(2)
string(4) "ahoj" refcount(4)
string(4) "ahoj" refcount(2)
string(4) "ahoj" refcount(4)
string(65) "very_long_key_that_will_not_be_deduplicated_by_simdjson_extension" refcount(2)
string(65) "very_long_key_that_will_not_be_deduplicated_by_simdjson_extension" refcount(2)
string(65) "very_long_key_that_will_not_be_deduplicated_by_simdjson_extension" refcount(2)
string(65) "very_long_key_that_will_not_be_deduplicated_by_simdjson_extension" refcount(2)
