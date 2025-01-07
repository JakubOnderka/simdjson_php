--TEST--
Bug #68938 compat (json_decode() decodes empty string without indicating error)
--FILE--
<?php
try {
    simdjson_decode("");
} catch (SimdJsonDecoderException $e) {
    printf("Caught %s: %s\n", get_class($e), $e->getMessage());
}
?>
--EXPECT--
Caught SimdJsonDecoderException: no JSON found
