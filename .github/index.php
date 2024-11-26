<?php
error_reporting(E_ALL | E_STRICT);
ini_set('display_errors', 1);

var_dump(simdjson_decode('{}'));
var_dump(simdjson_decode('[]'));
var_dump(simdjson_decode('[1,2,3]'));
