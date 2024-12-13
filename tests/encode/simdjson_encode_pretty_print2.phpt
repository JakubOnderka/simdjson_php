--TEST--
simdjson_encode() with JSON_PRETTY_PRINT on declared properties
--FILE--
<?php
#[AllowDynamicProperties]
class MyClass {
    public $x;
    public $y;
    public function __construct($x = 123, $y = []) {
        $this->x = $x;
        $this->y = $y;
    }
}

class HasNoProperties {}

echo simdjson_encode(new HasNoProperties()), "\n";
echo simdjson_encode(new HasNoProperties(), JSON_PRETTY_PRINT), "\n";

echo simdjson_encode(new MyClass()), "\n";
echo simdjson_encode(new MyClass(), JSON_PRETTY_PRINT), "\n";
$obj = new MyClass();
$obj->dynamic = new MyClass(null, []);
echo simdjson_encode($obj), "\n";
echo simdjson_encode($obj, JSON_PRETTY_PRINT), "\n";
$obj = new MyClass();
unset($obj->y);
echo simdjson_encode($obj), "\n";
echo simdjson_encode($obj, JSON_PRETTY_PRINT), "\n";
unset($obj->x);
echo simdjson_encode($obj), "\n";
echo simdjson_encode($obj, JSON_PRETTY_PRINT), "\n";
?>
--EXPECT--
{}
{}
{"x":123,"y":[]}
{
    "x": 123,
    "y": []
}
{"x":123,"y":[],"dynamic":{"x":null,"y":[]}}
{
    "x": 123,
    "y": [],
    "dynamic": {
        "x": null,
        "y": []
    }
}
{"x":123}
{
    "x": 123
}
{}
{}