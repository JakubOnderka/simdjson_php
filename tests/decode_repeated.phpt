--TEST--
simdjson_decode repeated strings
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