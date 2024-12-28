--TEST--
Test simdjson_encode() function : append newline
--FILE--
<?php
var_dump(simdjson_encode(null, SIMDJSON_APPEND_NEWLINE));
var_dump(simdjson_encode(true, SIMDJSON_APPEND_NEWLINE));
var_dump(simdjson_encode(false, SIMDJSON_APPEND_NEWLINE));
var_dump(simdjson_encode(0, SIMDJSON_APPEND_NEWLINE));
var_dump(simdjson_encode([], SIMDJSON_APPEND_NEWLINE));
var_dump(simdjson_encode("ahoj svete", SIMDJSON_APPEND_NEWLINE));

$s = fopen('php://stdout', 'w');
simdjson_encode_to_stream("ahoj svete", $s, SIMDJSON_APPEND_NEWLINE);
simdjson_encode_to_stream("ahoj svete", $s, SIMDJSON_APPEND_NEWLINE);
?>
--EXPECT--
string(5) "null
"
string(5) "true
"
string(6) "false
"
string(2) "0
"
string(3) "[]
"
string(13) ""ahoj svete"
"
"ahoj svete"
"ahoj svete"