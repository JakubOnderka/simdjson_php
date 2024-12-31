--TEST--
simdjson_encode() Recursion test with JsonSerializable, __debugInfo and var_export
--SKIPIF--
<?php if (PHP_VERSION_ID < 80300) echo "skip php 8.3+ only\n";
--FILE--
<?php

class SerializingTest implements JsonSerializable
{
    public $a = 1;

    public function __debugInfo()
    {
        return [ 'result' => var_export($this, true) ];
    }

    public function jsonSerialize(): mixed
    {
        var_dump($this);
        return $this;
    }
}

var_dump(simdjson_encode(new SerializingTest()));
echo "---------\n";
var_dump(new SerializingTest());

?>
--EXPECT--
object(SerializingTest)#1 (1) {
  ["result"]=>
  string(52) "\SerializingTest::__set_state(array(
   'a' => 1,
))"
}
string(7) "{"a":1}"
---------
object(SerializingTest)#1 (1) {
  ["result"]=>
  string(52) "\SerializingTest::__set_state(array(
   'a' => 1,
))"
}
