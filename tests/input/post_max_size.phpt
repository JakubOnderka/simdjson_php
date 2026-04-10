--TEST--
simdjson_decode_from_input POST post_max_size
--SKIPIF--
<?php
if (PHP_VERSION_ID < 80200) echo "skip error message is different for older PHP\n";
--INI--
post_max_size=5
--POST--
{"test":"ahoj"}
--FILE--
<?php
try {
    simdjson_decode_from_input(true);
}catch (Exception $e) {
    echo $e->getMessage();
}
?>
--EXPECTF--
Warning: PHP Request Startup: POST Content-Length of 15 bytes exceeds the limit of 5 bytes in Unknown on line 0
POST Content-Length of 15 bytes exceeds the limit of 5 bytes
