--TEST--
Test simdjson_encode() function : lazy objects
--SKIPIF--
<?php
if (PHP_VERSION_ID < 80400) echo "skip deduplication is supported since PHP 8.4\n";
?>
--FILE--
<?php
class Example
{
    public function __construct(public int $prop)
    {
        echo __METHOD__, "\n";
    }
}

$reflector = new ReflectionClass(Example::class);
$lazyObject = $reflector->newLazyGhost(function (Example $object) {
    // Initialize object in-place
    $object->__construct(1);
});

var_dump(simdjson_encode($lazyObject));
?>
--EXPECT--
Example::__construct
string(10) "{"prop":1}"
