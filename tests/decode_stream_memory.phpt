--TEST--
Test simdjson_decode_from_stream() function with memory buffer
--FILE--
<?php
// No data
try {
    simdjson_decode_from_stream(fopen("php://memory", "r"));
} catch (Exception $e) {
    echo $e->getMessage() . "\n";
}

// Read from end of stream where is no data anymore
$memory = fopen("php://memory", "w+");
fwrite($memory, "true");
try {
    simdjson_decode_from_stream($memory);
} catch (Exception $e) {
    echo $e->getMessage() . "\n";
}

// Read from middle of stream where is invalid JSON
$memory = fopen("php://memory", "w+");
fwrite($memory, "true");
fseek($memory, 2);
try {
    simdjson_decode_from_stream($memory);
} catch (Exception $e) {
    echo $e->getMessage() . "\n";
}

// Read from start of stream
$memory = fopen("php://memory", "w+");
fwrite($memory, "true");
fseek($memory, 0);
var_dump(simdjson_decode_from_stream($memory));
var_dump(ftell($memory));

// Skip first byte of stream (simple value)
$memory = fopen("php://memory", "w+");
fwrite($memory, " true");
fseek($memory, 1);
var_dump(simdjson_decode_from_stream($memory));
var_dump(ftell($memory));

// Skip first byte of stream (complex value)
$memory = fopen("php://memory", "w+");
fwrite($memory, " [1,2,3]");
fseek($memory, 1);
var_dump(simdjson_decode_from_stream($memory));

// Use filter
$memory = fopen("php://memory", "w+");
fwrite($memory, "TRUE");
fseek($memory, 0);
stream_filter_append($memory, 'string.tolower');
var_dump(simdjson_decode_from_stream($memory));
--EXPECT--
no JSON found
no JSON found
The JSON document has an improper structure: missing or superfluous commas, braces, missing keys, etc.
bool(true)
int(4)
bool(true)
int(5)
array(3) {
  [0]=>
  int(1)
  [1]=>
  int(2)
  [2]=>
  int(3)
}
bool(true)