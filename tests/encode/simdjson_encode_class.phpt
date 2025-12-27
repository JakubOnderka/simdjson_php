--TEST--
Test simdjson_encode() function : class
--FILE--
<?php
error_reporting(E_ALL ^ E_DEPRECATED);

class Test {
    public $a;
    private $b;
}

class JsonSerializableTestNull implements JsonSerializable {
    public function jsonSerialize(): mixed {
        return null;
    }
}

class JsonSerializableTestThis implements JsonSerializable {
    public function jsonSerialize(): mixed {
        return $this;
    }
}

$jsonSerializableNull = new JsonSerializableTestNull();
$jsonSerializableThis = new JsonSerializableTestThis();

$obj = new Test();
$obj->a = "test";

$objMixed = new Test();
$objMixed->a = "test";
$objMixed->dynamic = "test";

var_dump(simdjson_encode(new stdClass()));
var_dump(simdjson_encode(new Test()));
var_dump(simdjson_encode($obj));
var_dump(simdjson_encode($objMixed));
var_dump(simdjson_encode($jsonSerializableNull));
var_dump(simdjson_encode($jsonSerializableThis));

echo "\n";
var_dump(simdjson_encode(new stdClass(), SIMDJSON_PRETTY_PRINT));
var_dump(simdjson_encode(new Test(), SIMDJSON_PRETTY_PRINT));
var_dump(simdjson_encode($obj, SIMDJSON_PRETTY_PRINT));
var_dump(simdjson_encode($objMixed, SIMDJSON_PRETTY_PRINT));
var_dump(simdjson_encode($jsonSerializableNull, SIMDJSON_PRETTY_PRINT));
var_dump(simdjson_encode($jsonSerializableThis, SIMDJSON_PRETTY_PRINT));
?>
--EXPECT--
string(2) "{}"
string(10) "{"a":null}"
string(12) "{"a":"test"}"
string(29) "{"a":"test","dynamic":"test"}"
string(4) "null"
string(2) "{}"

string(2) "{}"
string(17) "{
    "a": null
}"
string(19) "{
    "a": "test"
}"
string(42) "{
    "a": "test",
    "dynamic": "test"
}"
string(4) "null"
string(2) "{}"
