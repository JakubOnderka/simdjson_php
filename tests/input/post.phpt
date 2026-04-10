--TEST--
simdjson_decode_from_input POST
--POST--
{}
--FILE--
<?php
var_dump(simdjson_decode_from_input(true));
?>
--EXPECT--
array(0) {
}
