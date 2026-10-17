--TEST--
simdjson_decode_iterate documents concatenated without whitespace separators
--FILE--
<?php
$json = '{"a":1}{"b":2}[1,2][3,4]';
foreach (simdjson_decode_iterate($json, true) as $value) {
    var_dump($value);
}

?>
--EXPECT--
array(1) {
  ["a"]=>
  int(1)
}
array(1) {
  ["b"]=>
  int(2)
}
array(2) {
  [0]=>
  int(1)
  [1]=>
  int(2)
}
array(2) {
  [0]=>
  int(3)
  [1]=>
  int(4)
}
