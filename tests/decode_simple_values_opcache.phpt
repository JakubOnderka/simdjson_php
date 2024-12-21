--TEST--
simdjson_decode simple values
--INI--
opcache.enable=1
opcache.enable_cli=1
--FILE--
<?php
$values = ["true", "false", '"NoAcl"', str_repeat("fal", 1) . "se", "123", "null"];
foreach ($values as $value) {
    $object = simdjson_decode($value);
    $array = simdjson_decode($value, true);
    var_dump($object);
    var_dump($object == $array);
}
?>
--EXPECTF--
bool(true)
bool(true)
bool(false)
bool(true)
string(5) "NoAcl"
bool(true)
bool(false)
bool(true)
int(123)
bool(true)
NULL
bool(true)