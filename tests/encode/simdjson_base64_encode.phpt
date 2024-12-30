--TEST--
Test SimdJsonBase64Encode
--FILE--
<?php
$base64Encode = new SimdJsonBase64Encode("ahoj");
var_dump($base64Encode->jsonSerialize());
var_dump((string)$base64Encode);
var_dump(json_encode(base64_encode("ahoj")));
var_dump(json_encode($base64Encode));
var_dump(simdjson_encode($base64Encode));
?>
--EXPECT--
string(8) "YWhvag=="
string(8) "YWhvag=="
string(10) ""YWhvag==""
string(10) ""YWhvag==""
string(10) ""YWhvag==""
