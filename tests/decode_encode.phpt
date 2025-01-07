--TEST--
Test simdjson_encode() and simdjson_decode() functions : no crash
--SKIPIF--
<?php
if (!($_ENV['SIMDJSON_HIGH_MEMORY_TESTS'] ?? null)) { echo "skip requires SIMDJSONHIGH_MEMORY_TESTS=1\n"; }
--FILE--
<?php
$filesToCheck = glob("jsonexamples/*.json");
array_push($filesToCheck, ...glob("jsonexamples/small/*.json"));
foreach ($filesToCheck as $file) {
    echo "Processing file $file\n";
    $file = file_get_contents($file);

    $decoded = simdjson_decode($file, true);
    simdjson_encode($decoded);
    simdjson_encode($decoded, SIMDJSON_PRETTY_PRINT);
    simdjson_encode($decoded, SIMDJSON_INVALID_UTF8_SUBSTITUTE);
    simdjson_encode($decoded, SIMDJSON_INVALID_UTF8_IGNORE);
    simdjson_encode($decoded, SIMDJSON_APPEND_NEWLINE);

    $decoded = simdjson_decode($file, false);
    simdjson_encode($decoded);
    simdjson_encode($decoded, SIMDJSON_PRETTY_PRINT);
    simdjson_encode($decoded, SIMDJSON_INVALID_UTF8_SUBSTITUTE);
    simdjson_encode($decoded, SIMDJSON_INVALID_UTF8_IGNORE);
    simdjson_encode($decoded, SIMDJSON_APPEND_NEWLINE);
}
--EXPECT--
Processing file jsonexamples/apache_builds.json
Processing file jsonexamples/canada.json
Processing file jsonexamples/citm_catalog.json
Processing file jsonexamples/github_events.json
Processing file jsonexamples/gsoc-2018.json
Processing file jsonexamples/instruments.json
Processing file jsonexamples/marine_ik.json
Processing file jsonexamples/mesh.json
Processing file jsonexamples/mesh.pretty.json
Processing file jsonexamples/numbers.json
Processing file jsonexamples/random.json
Processing file jsonexamples/stringifiedphp.json
Processing file jsonexamples/twitter.json
Processing file jsonexamples/twitterescaped.json
Processing file jsonexamples/update-center.json
Processing file jsonexamples/small/adversarial.json
Processing file jsonexamples/small/demo.json
Processing file jsonexamples/small/flatadversarial.json
Processing file jsonexamples/small/repeat.json
Processing file jsonexamples/small/truenull.json
Processing file jsonexamples/small/twitter_timeline.json
