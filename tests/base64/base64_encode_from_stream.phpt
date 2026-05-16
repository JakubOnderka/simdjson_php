--TEST--
Test simdjson_base64_encode_from_stream() function
--FILE--
<?php
$memoryStream = fopen("php://memory", "rw");
fwrite($memoryStream, "ahoj");
fseek($memoryStream, 0);
$encoded = simdjson_base64_encode_from_stream($memoryStream);
var_dump($encoded);
$decoded = simdjson_base64_decode($encoded);
var_dump($decoded);
?>
--EXPECT--
string(8) "YWhvag=="
string(4) "ahoj"
