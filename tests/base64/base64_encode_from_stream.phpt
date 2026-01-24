--TEST--
Test simdjson_base64_encode_from_stream() function
--FILE--
<?php
$memoryStream = fopen("php://memory", "rw");
fwrite($memoryStream, "ahoj");
fseek($memoryStream, 0);
$encoded = simdjson_base64_encode_from_stream($memoryStream);
echo $encoded . "\n";
$decoded = simdjson_base64_decode($encoded);
echo $decoded . "\n";
?>
--EXPECT--
YWhvag==
ahoj
