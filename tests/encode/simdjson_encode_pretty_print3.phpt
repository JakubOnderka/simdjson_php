--TEST--
simdjson_encode() with JSON_PRETTY_PRINT
--FILE--
<?php
$testArray = ['ahoj' => 'svete'];
$output = [];
$inner = &$output;
for ($i = 0; $i < 10; $i++) {
    $inner['next'] = $testArray;
    $inner = &$inner['next'];
}
echo simdjson_encode($output, SIMDJSON_PRETTY_PRINT);
echo json_encode($output, JSON_PRETTY_PRINT);
?>
--EXPECT--
{
    "next": {
        "ahoj": "svete",
        "next": {
            "ahoj": "svete",
            "next": {
                "ahoj": "svete",
                "next": {
                    "ahoj": "svete",
                    "next": {
                        "ahoj": "svete",
                        "next": {
                            "ahoj": "svete",
                            "next": {
                                "ahoj": "svete",
                                "next": {
                                    "ahoj": "svete",
                                    "next": {
                                        "ahoj": "svete",
                                        "next": {
                                            "ahoj": "svete"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}{
    "next": {
        "ahoj": "svete",
        "next": {
            "ahoj": "svete",
            "next": {
                "ahoj": "svete",
                "next": {
                    "ahoj": "svete",
                    "next": {
                        "ahoj": "svete",
                        "next": {
                            "ahoj": "svete",
                            "next": {
                                "ahoj": "svete",
                                "next": {
                                    "ahoj": "svete",
                                    "next": {
                                        "ahoj": "svete",
                                        "next": {
                                            "ahoj": "svete"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}