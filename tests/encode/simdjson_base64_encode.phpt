--TEST--
Test SimdJsonBase64Encode
--FILE--
<?php
echo "Base64 encode\n";
$base64Encode = new SimdJsonBase64Encode("ahoj");
var_dump($base64Encode->jsonSerialize());
var_dump((string)$base64Encode);
var_dump(json_encode(base64_encode("ahoj")));
var_dump(json_encode($base64Encode));
var_dump(simdjson_encode($base64Encode));
echo "Base64 URL encode\n";
$base64Encode = new SimdJsonBase64Encode("ahoj", true);
var_dump($base64Encode->jsonSerialize());
var_dump((string)$base64Encode);
var_dump(json_encode($base64Encode));
var_dump(simdjson_encode($base64Encode));
?>
--EXPECT--
Base64 encode
string(8) "YWhvag=="
string(8) "YWhvag=="
string(10) ""YWhvag==""
string(10) ""YWhvag==""
string(10) ""YWhvag==""
Base64 URL encode
string(6) "YWhvag"
string(6) "YWhvag"
string(8) ""YWhvag""
string(8) ""YWhvag""
