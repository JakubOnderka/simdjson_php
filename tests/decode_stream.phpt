--TEST--
Test simdjson_decode_from_stream() functions
--FILE--
<?php
$filesToCheck = glob("jsonexamples/*.json");
array_push($filesToCheck, ...glob("jsonexamples/small/*.json"));
foreach ($filesToCheck as $file) {
    echo "Processing file $file\n";
    simdjson_decode_from_stream(fopen($file, 'r'));
}

try {
    simdjson_decode_from_stream(fopen("php://memory", "r"));
} catch (Exception $e) {
    echo $e->getMessage();
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
no JSON found
