--TEST--
simdjson_is_valid test
--SKIPIF--
<?php if (PHP_VERSION_ID < 80300) echo "skip requires php 8.3+ for json_validate method\n";
--FILE--
<?php
function validate($input) {
    echo "Checking '$input'\n";
    var_dump(json_validate($input));
    var_dump(\simdjson_is_valid($input));
}

$json = file_get_contents(__DIR__ . DIRECTORY_SEPARATOR . '_files' . DIRECTORY_SEPARATOR . 'result.json');
$value = \simdjson_is_valid($json);
var_dump($value);

validate("true");
validate("false");
validate("null");
validate("[]");
validate("{}");
validate("{}}");
validate("1");
validate('{"corrupt": true,');
validate('{"corrupt" true}');
validate('Invalid JSON string');
validate('{"value": true}  ');
validate("{\"value\": true}\n\t ");
validate('{"value": true}{}');
validate('{"value": true}abc');
?>
--EXPECT--
bool(true)
Checking 'true'
bool(true)
bool(true)
Checking 'false'
bool(true)
bool(true)
Checking 'null'
bool(true)
bool(true)
Checking '[]'
bool(true)
bool(true)
Checking '{}'
bool(true)
bool(true)
Checking '{}}'
bool(false)
bool(false)
Checking '1'
bool(true)
bool(true)
Checking '{"corrupt": true,'
bool(false)
bool(false)
Checking '{"corrupt" true}'
bool(false)
bool(false)
Checking 'Invalid JSON string'
bool(false)
bool(false)
Checking '{"value": true}  '
bool(true)
bool(true)
Checking '{"value": true}
	 '
bool(true)
bool(true)
Checking '{"value": true}{}'
bool(false)
bool(false)
Checking '{"value": true}abc'
bool(false)
bool(false)