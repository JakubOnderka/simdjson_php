--TEST--
simdjson_is_valid depth
--FILE--
<?php
var_dump(simdjson_is_valid(str_repeat('[', 200000) . str_repeat(']', 199999), 5000));
?>
--EXPECT--
bool(false)