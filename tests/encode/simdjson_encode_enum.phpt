--TEST--
simdjson_encode() enum
--SKIPIF--
<?php if (PHP_VERSION_ID < 80100) echo "skip php 8.1+ only\n";
--FILE--
<?php

enum Suit: string
{
    case Hearts = 'Hearts';
    case Diamonds = 'Diamonds';
    case Clubs = 'Clubs';
    case Spades = 'Spades';
}

var_dump(simdjson_encode(Suit::Spades));
?>
--EXPECT--
string(8) ""Spades""