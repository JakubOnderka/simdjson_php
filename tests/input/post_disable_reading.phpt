--TEST--
simdjson_decode_from_input POST with disabled post reading
--INI--
enable_post_data_reading=Off
--POST--
{}
--FILE--
<?php
var_dump(simdjson_decode_from_input(true));
?>
--EXPECT--
array(0) {
}
