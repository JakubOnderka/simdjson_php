--TEST--
Test simdjson_encode() function : SplFixedArray
--SKIPIF--
<?php
if (PHP_VERSION_ID < 80200) echo "skip SplFixedArray implemenets jsonSerialize since PHP 8.2\n";
?>
--FILE--
<?php
error_reporting(E_ALL ^ E_DEPRECATED);

// Empty array
var_dump(simdjson_encode(new SplFixedArray(0)));

// Array with one element
$array = new SplFixedArray(1);
$array[0] = 1;
var_dump(simdjson_encode($array));

// Array with size 2 but with only one element
$array = new SplFixedArray(2);
$array[0] = 1;
var_dump(simdjson_encode($array));

// Object with dynamic property - it is not serialized to JSON
$array = new SplFixedArray(2);
$array[0] = 1;
$array->test = "test";
var_dump(simdjson_encode($array));

class CustomFixedArray extends SplFixedArray {
}
var_dump(simdjson_encode(new CustomFixedArray(0)));

$array = new CustomFixedArray(1);
$array[0] = 1;
var_dump(simdjson_encode($array));

class FixedArrayWithCustomJsonSerialize extends SplFixedArray {
    public function jsonSerialize(): array {
        return [2];
    }
}
$array = new FixedArrayWithCustomJsonSerialize(1);
$array[0] = 1;
var_dump(simdjson_encode($array));
--EXPECT--
string(2) "[]"
string(3) "[1]"
string(8) "[1,null]"
string(8) "[1,null]"
string(2) "[]"
string(3) "[1]"
string(3) "[2]"
