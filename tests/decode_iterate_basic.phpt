--TEST--
simdjson_decode_iterate basic NDJSON iteration
--FILE--
<?php
$json = "{\"a\":1}\n{\"b\":2}\n[1,2,3]\n\"hello\"\n42\ntrue\nfalse\nnull\n";
foreach (simdjson_decode_iterate($json) as $index => $value) {
    echo $index, ': ', json_encode($value), "\n";
}

?>
--EXPECT--
0: {"a":1}
1: {"b":2}
2: [1,2,3]
3: "hello"
4: 42
5: true
6: false
7: null
