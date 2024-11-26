--TEST--
simdjson_decode small file
--FILE--
<?php
$json = file_get_contents(__DIR__ . '/_files/short.json');
$array = simdjson_decode($json, true);
var_dump($array);
?>
--EXPECTF--
array(3) {
  ["major"]=>
  int(2)
  ["minor"]=>
  int(5)
  ["hotfix"]=>
  int(1)
}
