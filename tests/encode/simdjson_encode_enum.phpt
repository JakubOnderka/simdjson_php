--TEST--
simdjson_encode() enum
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