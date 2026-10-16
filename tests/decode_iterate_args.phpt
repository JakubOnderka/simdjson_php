--TEST--
simdjson_decode_iterate args test
--FILE--
<?php
$reflection = new \ReflectionFunction('\simdjson_decode_iterate');
echo $reflection;

?>
--EXPECTF--
Function [ <internal:simdjson> function simdjson_decode_iterate ] {

  - Parameters [4] {
    Parameter #0 [ <required> string $json ]
    Parameter #1 [ <optional> bool $associative%s ]
    Parameter #2 [ <optional> int $depth%s ]
    Parameter #3 [ <optional> int $batch_size%s ]
  }
  - Return [ SimdJsonDecodeIterator ]
}
