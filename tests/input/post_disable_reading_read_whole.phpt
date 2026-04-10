--TEST--
simdjson_decode_from_input POST with disabled post reading
--INI--
enable_post_data_reading=Off
--POST--
{}
--FILE--
<?php
var_dump(file_get_contents("php://input"));
var_dump(simdjson_decode_from_input(true));
var_dump(file_get_contents("php://input"));
?>
--EXPECT--
string(2) "{}"
array(0) {
}
string(2) "{}"
