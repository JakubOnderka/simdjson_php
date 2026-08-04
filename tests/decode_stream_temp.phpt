--TEST--
Test simdjson_decode_from_stream() function with temp buffer
--FILE--
<?php
// No data
try {
    simdjson_decode_from_stream(fopen("php://temp", "r"));
} catch (Exception $e) {
    echo $e->getMessage() . "\n";
}

// Read from end of stream where is no data anymore
$temp = fopen("php://temp", "w+");
fwrite($temp, "true");
try {
    simdjson_decode_from_stream($temp);
} catch (Exception $e) {
    echo $e->getMessage() . "\n";
}

// Read from middle of stream where is invalid JSON
$temp = fopen("php://temp", "w+");
fwrite($temp, "true");
fseek($temp, 2);
try {
    simdjson_decode_from_stream($temp);
} catch (Exception $e) {
    echo $e->getMessage() . "\n";
}

// Read from start of stream
$temp = fopen("php://temp", "w+");
fwrite($temp, "true");
fseek($temp, 0);
var_dump(simdjson_decode_from_stream($temp));
var_dump(ftell($temp));

// Decode temp stream that is saved in file
$temp = fopen("php://temp", "w+");
fwrite($temp, "\"" . str_repeat("a", 1024 * 1024 * 2) . "\"");
fseek($temp, 0);
var_dump(strlen(simdjson_decode_from_stream($temp)));
--EXPECT--
no JSON found
no JSON found
The JSON document has an improper structure: missing or superfluous commas, braces, missing keys, etc.
bool(true)
int(4)
int(2097152)