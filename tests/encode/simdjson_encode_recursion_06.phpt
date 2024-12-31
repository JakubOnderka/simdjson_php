--TEST--
simdjson_encode() Recursion test with JsonSerializable and serialize
--FILE--
<?php

class JsonEncodeFirstTest implements JsonSerializable
{
    public $a = 1;

    public function __serialize()
    {
        return [ 'result' => $this->a ];
    }

    public function jsonSerialize(): mixed
    {
        return [ 'serialize' => serialize($this) ];
    }
}

class SerializeFirstTest implements JsonSerializable
{
    public $a = 1;

    public function __serialize()
    {
        return [ 'result' => simdjson_encode($this) ];
    }

    public function jsonSerialize(): mixed
    {
        return [ 'json' => serialize($this) ];
    }
}

var_dump(simdjson_encode(new JsonEncodeFirstTest()));
try {
var_dump(serialize(new SerializeFirstTest()));
} catch (Exception $e) {
    echo $e->getMessage();
}
?>
--EXPECT--
string(68) "{"serialize":"O:19:\"JsonEncodeFirstTest\":1:{s:6:\"result\";i:1;}"}"
Recursion detected
