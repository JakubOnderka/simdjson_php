--TEST--
simdjson_decode_iterate associative vs object mode
--FILE--
<?php
$json = '{"a":{"b":[1,2,{"c":3}]}}';

$value = null;
foreach (simdjson_decode_iterate($json, true) as $value) {
}
var_dump($value);

$value = null;
foreach (simdjson_decode_iterate($json, false) as $value) {
}
var_dump($value);

?>
--EXPECTF--
array(1) {
  ["a"]=>
  array(1) {
    ["b"]=>
    array(3) {
      [0]=>
      int(1)
      [1]=>
      int(2)
      [2]=>
      array(1) {
        ["c"]=>
        int(3)
      }
    }
  }
}
object(stdClass)#%d (1) {
  ["a"]=>
  object(stdClass)#%d (1) {
    ["b"]=>
    array(3) {
      [0]=>
      int(1)
      [1]=>
      int(2)
      [2]=>
      object(stdClass)#%d (1) {
        ["c"]=>
        int(3)
      }
    }
  }
}
