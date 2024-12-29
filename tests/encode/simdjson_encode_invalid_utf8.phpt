--TEST--
json_encode() invalid UTF8
--FILE--
<?php
function json_encode_invalid_utf8($str) {
    var_dump(bin2hex(json_encode($str, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE)));
    var_dump(bin2hex(simdjson_encode($str, JSON_INVALID_UTF8_SUBSTITUTE)));
}
echo "Test 1\n";
json_encode_invalid_utf8("\x61\xb0\x62");
echo "Test 2\n";
json_encode_invalid_utf8("\x61\xf0\x80\x80\x41");
echo "Test 3\n";
json_encode_invalid_utf8("\x61\xf0\x80\x80\x41\n");
echo "Test 4\n";
json_encode_invalid_utf8("\xb0\x62");
echo "Test 5\n";
json_encode_invalid_utf8("\xb0\xb0");
echo "Test 6\n";
json_encode_invalid_utf8("řež\xb0");
echo "Test 7\n";
json_encode_invalid_utf8("řež\xb0řež");
echo "Done\n";
?>
--EXPECT--
Test 1
string(14) "2261efbfbd6222"
string(14) "2261efbfbd6222"
Test 2
string(14) "2261efbfbd4122"
string(14) "2261efbfbd4122"
Test 3
string(18) "2261efbfbd415c6e22"
string(18) "2261efbfbd415c6e22"
Test 4
string(12) "22efbfbd6222"
string(12) "22efbfbd6222"
Test 5
string(16) "22efbfbdefbfbd22"
string(16) "22efbfbdefbfbd22"
Test 6
string(20) "22c59965c5beefbfbd22"
string(20) "22c59965c5beefbfbd22"
Test 7
string(30) "22c59965c5beefbfbdc59965c5be22"
string(30) "22c59965c5beefbfbdc59965c5be22"
Done
