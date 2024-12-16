--TEST--
Test simdjson_encode() function : append newline
--FILE--
<?php
var_dump(simdjson_encode("ahoj svete", SIMDJSON_APPEND_NEWLINE));

$s = fopen('php://stdout', 'w');
simdjson_encode_to_stream("ahoj svete", $s, SIMDJSON_APPEND_NEWLINE);
simdjson_encode_to_stream("ahoj svete", $s, SIMDJSON_APPEND_NEWLINE);
?>
--EXPECT--
string(13) ""ahoj svete"
"
"ahoj svete"
"ahoj svete"