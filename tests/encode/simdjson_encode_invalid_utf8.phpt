--TEST--
json_encode() invalid UTF8
--FILE--
<?php
function json_encode_invalid_utf8($str) {
    var_dump(json_encode($str));
    var_dump(json_encode($str, JSON_INVALID_UTF8_IGNORE));
    var_dump(json_encode($str, JSON_INVALID_UTF8_SUBSTITUTE));
    var_dump(json_encode($str, JSON_UNESCAPED_UNICODE));
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
echo "Done\n";
?>
--EXPECT--
Test 1
bool(false)
string(4) ""ab""
string(10) ""a\ufffdb""
bool(false)
string(14) "2261efbfbd6222"
string(14) "2261efbfbd6222"
Test 2
bool(false)
string(4) ""aA""
string(10) ""a\ufffdA""
bool(false)
string(14) "2261efbfbd4122"
string(14) "2261efbfbd4122"
Test 3
bool(false)
string(6) ""aA\n""
string(12) ""a\ufffdA\n""
bool(false)
string(18) "2261efbfbd415c6e22"
string(18) "2261efbfbd415c6e22"
Test 4
bool(false)
string(3) ""b""
string(9) ""\ufffdb""
bool(false)
string(12) "22efbfbd6222"
string(12) "22efbfbd6222"
Test 5
bool(false)
string(2) """"
string(14) ""\ufffd\ufffd""
bool(false)
string(16) "22efbfbdefbfbd22"
string(16) "22efbfbdefbfbd22"
Done
