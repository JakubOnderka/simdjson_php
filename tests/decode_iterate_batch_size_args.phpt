--TEST--
simdjson_decode_iterate rejects a negative batch_size argument
--FILE--
<?php
try {
    simdjson_decode_iterate('1', false, 512, -1);
    echo "no exception thrown\n";
} catch (\ValueError $e) {
    echo $e->getMessage(), "\n";
}

// batch_size of 0 means "pick an appropriate default"
foreach (simdjson_decode_iterate('[1,2,3]', false, 512, 0) as $value) {
    var_dump($value);
}

?>
--EXPECT--
simdjson_decode_iterate(): Argument #4 ($batch_size) must be greater than or equal to 0
array(3) {
  [0]=>
  int(1)
  [1]=>
  int(2)
  [2]=>
  int(3)
}
