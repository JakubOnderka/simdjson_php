--TEST--
Test simdjson_encode() function : compare with json_encode
--FILE--
<?php
$files = glob("jsonexamples/*.json");
foreach ($files as $file) {
    if ($file === "jsonexamples/gsoc-2018.json") {
        continue; // skip as gsoc-2018 contains unicode chars that simdjson and json handles differently
    }
    echo "Processing file $file\n";
    $decoded = simdjson_decode(file_get_contents($file), true);
    $simdjsonEncoded = simdjson_encode($decoded);
    $stdEncoded = json_encode($decoded, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if ($stdEncoded !== $simdjsonEncoded) {
        echo "Different!\n";
    } else {
        echo "OK\n";
    }
}
--EXPECT--
Processing file jsonexamples/apache_builds.json
OK
Processing file jsonexamples/canada.json
OK
Processing file jsonexamples/citm_catalog.json
OK
Processing file jsonexamples/github_events.json
OK
Processing file jsonexamples/instruments.json
OK
Processing file jsonexamples/marine_ik.json
OK
Processing file jsonexamples/mesh.json
OK
Processing file jsonexamples/mesh.pretty.json
OK
Processing file jsonexamples/numbers.json
OK
Processing file jsonexamples/random.json
OK
Processing file jsonexamples/stringifiedphp.json
OK
Processing file jsonexamples/twitter.json
OK
Processing file jsonexamples/twitterescaped.json
OK
Processing file jsonexamples/update-center.json
OK
