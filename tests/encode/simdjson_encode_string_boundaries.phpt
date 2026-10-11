--TEST--
simdjson_encode string escaping matches json_encode for all lengths and escape positions
--FILE--
<?php
$bad = 0;
foreach (["\"", "\\", "\n", "\x01", "\x1f"] as $special) {
    for ($len = 0; $len <= 70; $len++) {
        $clean = str_repeat('a', $len);
        if (simdjson_encode($clean) !== json_encode($clean)) {
            $bad++;
        }
        for ($pos = 0; $pos < $len; $pos++) {
            $s = $clean;
            $s[$pos] = $special;
            if (simdjson_encode($s) !== json_encode($s)) {
                $bad++;
            }
        }
    }
}
var_dump($bad);
?>
--EXPECT--
int(0)
