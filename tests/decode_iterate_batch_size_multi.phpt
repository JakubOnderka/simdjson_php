--TEST--
simdjson_decode_iterate with a batch_size smaller than the whole input (multiple internal batches)
--FILE--
<?php
$documents = [];
for ($i = 0; $i < 50; $i++) {
    $documents[] = json_encode(['n' => $i]);
}
$json = implode("\n", $documents) . "\n";

$decoded = [];
foreach (simdjson_decode_iterate($json, true, 512, 64) as $index => $value) {
    $decoded[$index] = $value['n'];
}

var_dump($decoded === range(0, 49));

?>
--EXPECT--
bool(true)
