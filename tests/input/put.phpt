--TEST--
simdjson_decode_from_input PUT
--PUT--
{}
--FILE--
<?php
var_dump(simdjson_decode_from_input(true));
?>
--EXPECT--
array(0) {
}
