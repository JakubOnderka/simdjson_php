--TEST--
simdjson_decode_iterate is a forward-only iterator: rewind() after advancing throws
--FILE--
<?php
$it = simdjson_decode_iterate('1 2 3');

// Before the first rewind()/advance, the iterator is not yet valid.
var_dump($it->valid());
var_dump($it->current());
var_dump($it->key());

foreach ($it as $index => $value) {
    var_dump($index, $value);
    break;
}

try {
    $it->rewind();
    echo "no exception thrown\n";
} catch (\Error $e) {
    echo get_class($e), ': ', $e->getMessage(), "\n";
}

?>
--EXPECT--
bool(false)
NULL
int(-1)
int(0)
int(1)
Error: Cannot rewind a SimdJsonDecodeIterator that has already been advanced
