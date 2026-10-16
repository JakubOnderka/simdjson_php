--TEST--
simdjson_decode_iterate throws an exception mid-stream, keeping previously decoded documents
--FILE--
<?php
$it = simdjson_decode_iterate("{\"a\":1}\n{invalid}\n{\"b\":2}\n");

$decoded = [];
try {
    foreach ($it as $value) {
        $decoded[] = $value;
    }
    echo "no exception thrown\n";
} catch (\RuntimeException $e) {
    echo get_class($e), ': ', $e->getMessage(), "\n";
}

var_dump($decoded);

?>
--EXPECTF--
SimdJsonDecoderException: The JSON document has an improper structure: missing or superfluous commas, braces, missing keys, etc.
array(1) {
  [0]=>
  object(stdClass)#%d (1) {
    ["a"]=>
    int(1)
  }
}
