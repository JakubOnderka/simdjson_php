--TEST--
Test simdjson_encode() function : compare with json_encode
--FILE--
<?php
$filesToCheck  = ["apache_builds.json", "citm_catalog.json", "github_events.json", "instruments.json", "random.json", "stringifiedphp.json", "twitter.json", "twitterescaped.json", "update-center.json"];
foreach ($filesToCheck as $file) {
    echo "Processing file $file\n";
    $decoded = simdjson_decode(file_get_contents("jsonexamples/" . $file), true);
    $simdjsonEncoded = simdjson_encode($decoded);
    $stdEncoded = json_encode($decoded, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if ($stdEncoded !== $simdjsonEncoded) {
        echo "Different!\n";
    } else {
        echo "OK\n";
    }
}
--EXPECT--
Processing file apache_builds.json
OK
Processing file citm_catalog.json
OK
Processing file github_events.json
OK
Processing file instruments.json
OK
Processing file random.json
OK
Processing file stringifiedphp.json
OK
Processing file twitter.json
OK
Processing file twitterescaped.json
OK
Processing file update-center.json
OK
