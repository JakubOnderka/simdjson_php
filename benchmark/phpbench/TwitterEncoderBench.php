<?php

declare(strict_types=1);

namespace SimdjsonBench;

use PhpBench\Benchmark\Metadata\Annotations\Subject;

if (!extension_loaded('simdjson')) {
    exit;
}

/**
 * @Revs(5)
 * @Iterations(5)
 * @Warmup(3)
 * @OutputTimeUnit("milliseconds", precision=5)
 * @BeforeMethods({"init"})
 * @Groups({"decode"})
 */
class TwitterEncoderBench
{
    /**
     * @var mixed
     */
    private $json;

    public function init(): void
    {
        $file = file_get_contents(__DIR__ . '/../../jsonexamples/twitter.json');
        $this->json = simdjson_decode($file);
    }

    /**
     * @Subject()
     */
    public function jsonEncode(): void
    {
        json_encode($this->json);
    }

    /**
     * @Subject()
     */
    public function jsonEncodePretty(): void
    {
        json_encode($this->json, JSON_PRETTY_PRINT);
    }

    /**
     * @Subject()
     */
    public function simdjsonEncode()
    {
        simdjson_encode($this->json);
    }

    /**
     * @Subject()
     */
    public function simdjsonEncodePretty()
    {
        simdjson_encode($this->json, JSON_PRETTY_PRINT);
    }
}
