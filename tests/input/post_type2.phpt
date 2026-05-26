--TEST--
Read POST from php://input with content-type application/json
--POST_RAW--
Content-Type: application/json
{}
--FILE--
<?php
var_dump(file_get_contents("php://input"));
?>
--EXPECT--
string(2) "{}"
