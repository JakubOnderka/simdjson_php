--TEST--
simdjson_decode converts integers exceeding 64 bits to float, like json_decode
--SKIPIF--
<?php if (PHP_INT_SIZE < 8) echo "skip 64-bit test only\n"; ?>
--INI--
serialize_precision=20
--FILE--
<?php
$json = '[18446744073709551616, -9223372036854775809, -18446744073709551617, 123456789012345678901234567890, {"a": 99999999999999999999999}]';
foreach ([false, true] as $assoc) {
    $decoded = simdjson_decode($json, $assoc);
    $expected = json_decode($json, $assoc);
    var_dump($decoded == $expected);
}
var_dump(simdjson_decode('{"a":[1e2,340282366920938463463374607431768211456]}', true));
var_dump(simdjson_key_value('{"a":[1,340282366920938463463374607431768211456]}', 'a/1'));
var_dump(simdjson_decode('-340282366920938463463374607431768211456'));
var_dump(simdjson_decode('1' . str_repeat('0', 400)));
var_dump(simdjson_decode('-1' . str_repeat('0', 400)));
var_dump(simdjson_decode('[123456789012345678901234567890123456789]')[0] === json_decode('[123456789012345678901234567890123456789]')[0]);
?>
--EXPECT--
bool(true)
bool(true)
array(1) {
  ["a"]=>
  array(2) {
    [0]=>
    float(100)
    [1]=>
    float(3.4028236692093846346E+38)
  }
}
float(3.4028236692093846346E+38)
float(-3.4028236692093846346E+38)
float(INF)
float(-INF)
bool(true)
