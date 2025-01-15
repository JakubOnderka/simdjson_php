--TEST--
simdjson_decode keys with the same name
--FILE--
<?php
var_dump(\simdjson_decode('{"ahoj":"svete","ahoj":"kamo"}', false));
var_dump(\simdjson_decode('{"ahoj":"svete","ahoj":"kamo"}', true));
?>
--EXPECTF--
object(stdClass)#1 (1) {
  ["ahoj"]=>
  string(4) "kamo"
}
array(1) {
  ["ahoj"]=>
  string(4) "kamo"
}
