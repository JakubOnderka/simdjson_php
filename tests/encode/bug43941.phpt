--TEST--
Bug #43941 (json_encode() invalid UTF-8)
--FILE--
<?php

var_dump(simdjson_encode("abc"));
try {
    var_dump(simdjson_encode("ab\xE0"));
} catch (Exception $e) {
    var_dump($e->getMessage());
}

echo "Done\n";
?>
--EXPECT--
string(5) ""abc""
string(56) "Malformed UTF-8 characters, possibly incorrectly encoded"
Done