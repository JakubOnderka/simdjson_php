--TEST--
Test SimdJsonBase64Encode with null value
--SKIPIF--
<?php if (PHP_VERSION_ID < 80100) echo "skip php 8.1+ only\n";
--FILE--
<?php
$base64Encode = new SimdJsonBase64Encode(null);
var_dump($base64Encode->jsonSerialize());
var_dump(simdjson_encode($base64Encode));
?>
--EXPECTF--
Deprecated: SimdJsonBase64Encode::__construct(): Passing null to parameter #1 ($string) of type string is deprecated in %s on line %d
string(0) ""
string(2) """"
