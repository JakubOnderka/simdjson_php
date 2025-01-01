--TEST--
json_encode() invalid UTF8 2
--FILE--
<?php

$examples = array(
    'Valid ASCII' => "a",
    'Valid 2 Octet Sequence' => "\xc3\xb1",
    'Invalid 2 Octet Sequence' => "\xc3\x28",
    'Invalid Sequence Identifier' => "\xa0\xa1",
    'Valid 3 Octet Sequence' => "\xe2\x82\xa1",
    'Invalid 3 Octet Sequence (in 2nd Octet)' => "\xe2\x28\xa1",
    'Invalid 3 Octet Sequence (in 3rd Octet)' => "\xe2\x82\x28",
    'Valid 4 Octet Sequence' => "\xf0\x90\x8c\xbc",
    'Invalid 4 Octet Sequence (in 2nd Octet)' => "\xf0\x28\x8c\xbc",
    'Invalid 4 Octet Sequence (in 3rd Octet)' => "\xf0\x90\x28\xbc",
    'Invalid 4 Octet Sequence (in 4th Octet)' => "\xf0\x28\x8c\x28",
    'Valid 5 Octet Sequence (but not Unicode!)' => "\xf8\xa1\xa1\xa1\xa1",
    'Valid 6 Octet Sequence (but not Unicode!)' => "\xfc\xa1\xa1\xa1\xa1\xa1",
);
foreach ($examples as $name => $value) {
    echo "Checking $name\n";
    var_dump(bin2hex(json_encode($value, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE)));
    var_dump(bin2hex(simdjson_encode($value, JSON_INVALID_UTF8_SUBSTITUTE)));
}
echo "Done\n";
?>
--EXPECT--
Checking Valid ASCII
string(6) "226122"
string(6) "226122"
Checking Valid 2 Octet Sequence
string(8) "22c3b122"
string(8) "22c3b122"
Checking Invalid 2 Octet Sequence
string(12) "22efbfbd2822"
string(12) "22efbfbd2822"
Checking Invalid Sequence Identifier
string(16) "22efbfbdefbfbd22"
string(16) "22efbfbdefbfbd22"
Checking Valid 3 Octet Sequence
string(10) "22e282a122"
string(10) "22e282a122"
Checking Invalid 3 Octet Sequence (in 2nd Octet)
string(18) "22efbfbd28efbfbd22"
string(18) "22efbfbd28efbfbd22"
Checking Invalid 3 Octet Sequence (in 3rd Octet)
string(12) "22efbfbd2822"
string(12) "22efbfbd2822"
Checking Valid 4 Octet Sequence
string(12) "22f0908cbc22"
string(12) "22f0908cbc22"
Checking Invalid 4 Octet Sequence (in 2nd Octet)
string(24) "22efbfbd28efbfbdefbfbd22"
string(24) "22efbfbd28efbfbdefbfbd22"
Checking Invalid 4 Octet Sequence (in 3rd Octet)
string(18) "22efbfbd28efbfbd22"
string(18) "22efbfbd28efbfbd22"
Checking Invalid 4 Octet Sequence (in 4th Octet)
string(20) "22efbfbd28efbfbd2822"
string(20) "22efbfbd28efbfbd2822"
Checking Valid 5 Octet Sequence (but not Unicode!)
string(34) "22efbfbdefbfbdefbfbdefbfbdefbfbd22"
string(34) "22efbfbdefbfbdefbfbdefbfbdefbfbd22"
Checking Valid 6 Octet Sequence (but not Unicode!)
string(40) "22efbfbdefbfbdefbfbdefbfbdefbfbdefbfbd22"
string(40) "22efbfbdefbfbdefbfbdefbfbdefbfbdefbfbd22"
Done
