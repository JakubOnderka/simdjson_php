<?php
// Repeat the operation to make benchmark results less random.
const ITERATIONS = 4000;

// Print the amount of nanoseconds taken on average for the functions, as well as the relative amount of time taken compared to json_decode
echo "filename|json_encode|simdjson_encode|relative_encode|\n---|:--:|---:|---:|---:|--:\n";

$simdjsonEncodeTotal = $jsonEncodeTotal = 0;
foreach (glob(__DIR__.'/../jsonexamples/twitter.json') as $item) {
    $fileContent = file_get_contents($item);
    $jsonArray = json_decode($fileContent, true);

    $start = hrtime(true);
    for ($i = 0; $i < ITERATIONS; $i++) { simdjson_encode($jsonArray); }
    $elapsed = hrtime(true);
    $simdjsonEncode = (int)(($elapsed - $start) / ITERATIONS);

    $start = hrtime(true);
    for ($i = 0; $i < ITERATIONS; $i++) { json_encode($jsonArray); }
    $elapsed = hrtime(true);
    $jsonEncode = (int)(($elapsed - $start) / ITERATIONS);

    $simdjsonEncodeTotal += $simdjsonEncode;
    $jsonEncodeTotal += $jsonEncode;

    $relativeEncode = sprintf('%.2fx', $simdjsonEncode / $jsonEncode);
    echo basename($item)."|$jsonEncode|$simdjsonEncode|$relativeEncode\n";
}

$relativeDecodeTotal = sprintf('%.2fx', $simdjsonEncodeTotal / $jsonEncodeTotal);
echo "Total|$jsonEncodeTotal|$simdjsonEncodeTotal|$relativeDecodeTotal\n";
