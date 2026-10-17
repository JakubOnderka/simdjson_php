--TEST--
simdjson_decode_iterate returns an Iterator implementation
--FILE--
<?php
$it = simdjson_decode_iterate('1');
var_dump($it instanceof Iterator);
var_dump($it instanceof SimdJsonDecodeIterator);

?>
--EXPECT--
bool(true)
bool(true)
