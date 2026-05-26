--TEST--
simdjson_decode_from_input POST with content-type application/json
--POST_RAW--
Content-Type: application/json
{}
--FILE--
<?php
var_dump(simdjson_decode_from_input(true));
?>
--EXPECT--
array(0) {
}
