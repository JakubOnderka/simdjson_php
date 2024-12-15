--TEST--
An error is thrown when an unsupported type is encoded
--FILE--
<?php

$resource = fopen(__FILE__, "r");

var_dump($resource);

try {
    var_dump(simdjson_encode($resource));
} catch (Exception $e) {
    var_dump($e->getMessage());
}

?>
--EXPECTF--
resource(%d) of type (stream)
string(21) "Type is not supported"