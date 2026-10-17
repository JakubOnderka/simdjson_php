--TEST--
simdjson_decode_iterate with an empty string yields no documents
--FILE--
<?php
$it = simdjson_decode_iterate('');
var_dump(iterator_to_array($it));
var_dump($it->valid());

$it2 = simdjson_decode_iterate("   \n\t  ");
var_dump(iterator_to_array($it2));

?>
--EXPECT--
array(0) {
}
bool(false)
array(0) {
}
