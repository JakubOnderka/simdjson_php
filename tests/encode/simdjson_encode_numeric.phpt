--TEST--
Test simdjson_encode() function with numeric flag
--INI--
serialize_precision=-1
--FILE--
<?php
var_dump(
    simdjson_encode("1"),
    simdjson_encode("9.4324"),
    simdjson_encode(array("122321", "3232595.33423"))
);
?>
--EXPECT--
string(3) ""1""
string(8) ""9.4324""
string(26) "["122321","3232595.33423"]"