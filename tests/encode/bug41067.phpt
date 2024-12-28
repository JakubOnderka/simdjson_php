--TEST--
Bug #41067 (json_encode() problem with UTF-16 input)
--FILE--
<?php
$single_barline = "\360\235\204\200";
$array = array($single_barline);
print bin2hex($single_barline) . "\n";
// print $single_barline . "\n\n";
$json = simdjson_encode($array);
print $json . "\n\n";
$json_decoded = simdjson_decode($json, true);
// print $json_decoded[0] . "\n";
print bin2hex($json_decoded[0]) . "\n";
print "END\n";
?>
--EXPECT--
f09d8480
["𝄀"]

f09d8480
END