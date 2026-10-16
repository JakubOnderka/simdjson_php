--TEST--
simdjson_encode substitutes malformed UTF-8 without consuming subsequent valid characters
--FILE--
<?php
$replacement = "\xEF\xBF\xBD";

$cases = [
    'stray continuation' => ["\x80", $replacement],
    'consecutive invalid bytes' => ["\x80\xBF\xFF", str_repeat($replacement, 3)],
    'invalid leading bytes' => ["\xC0\xC1\xF5", str_repeat($replacement, 3)],

    'truncated two-byte sequence' => ["\xC2", $replacement],
    'truncated three-byte sequence, one byte' => ["\xE2", $replacement],
    'truncated three-byte sequence, two bytes' => ["\xE2\x82", $replacement],
    'truncated four-byte sequence, one byte' => ["\xF0", $replacement],
    'truncated four-byte sequence, two bytes' => ["\xF0\x90", $replacement],
    'truncated four-byte sequence, three bytes' => ["\xF0\x90\x8C", $replacement],

    'two-byte sequence before ASCII' => ["\xC2A", $replacement . 'A'],
    'three-byte sequence before ASCII, second byte' => ["\xE2A", $replacement . 'A'],
    'three-byte sequence before ASCII, third byte' => ["\xE2\x82A", $replacement . 'A'],
    'four-byte sequence before ASCII, second byte' => ["\xF0A", $replacement . 'A'],
    'four-byte sequence before ASCII, third byte' => ["\xF0\x90A", $replacement . 'A'],
    'four-byte sequence before ASCII, fourth byte' => ["\xF0\x90\x8CA", $replacement . 'A'],

    'preserve valid two-byte character' => ["\xE2\xC3\xB1", $replacement . "\xC3\xB1"],
    'preserve valid three-byte character' => ["\xF0\x90\xE2\x82\xAC", $replacement . "\xE2\x82\xAC"],
    'preserve valid four-byte character' => ["\xC2\xF0\x9F\x98\x80", $replacement . "\xF0\x9F\x98\x80"],

    // Invalid non-leading bytes belong to the same malformed sequence.
    'two-byte sequence with invalid tail' => ["\xC2\xFF", $replacement],
    'three-byte sequence with invalid tails' => ["\xE2\xFF\xC0", $replacement],
    'four-byte sequence with invalid tails' => ["\xF0\xFF\xC0\xC1", $replacement],
];

foreach ($cases as $name => [$input, $expected]) {
    // Also exercise escaping and preservation of valid text around the error.
    foreach (['bare', 'surrounded'] as $context) {
        $prefix = $context === 'surrounded' ? "before\"\\\n\xC3\xB1" : '';
        $suffix = $context === 'surrounded' ? "\xE2\x82\xAC\tend" : '';

        // Encode the explicitly specified, valid repaired string as the oracle.
        $expectedJson = json_encode(
            $prefix . $expected . $suffix,
            JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
        );
        $actual = simdjson_encode(
            $prefix . $input . $suffix,
            SIMDJSON_INVALID_UTF8_SUBSTITUTE
        );

        if ($actual !== $expectedJson) {
            echo "FAIL: $name ($context)\n";
            echo "Expected: ", bin2hex($expectedJson), "\n";
            echo "Actual:   ", bin2hex($actual), "\n";
        }
    }
}
echo "Done\n";
?>
--EXPECT--
Done
