--TEST--
simdjson_decode_from_input empty POST
--POST--
--FILE--
<?php
try {
    simdjson_decode_from_input(true);
} catch (Exception $e) {
    echo $e->getMessage();
}
?>
--EXPECT--
no JSON found
