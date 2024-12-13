--TEST--
simdjson_encode() Recursion test with just JsonSerializable
--FILE--
<?php

class SerializingTest implements JsonSerializable
{
    public $a = 1;

    private $b = 'hide';

    protected $c = 'protect';

    public function jsonSerialize(): mixed
    {
        try {
            $result = simdjson_encode($this);
        } catch (Exception $e) {
            $result = false;
        }
        var_dump($result);
        return $this;
    }
}

var_dump(simdjson_encode(new SerializingTest()));
?>
--EXPECT--
bool(false)
string(7) "{"a":1}"