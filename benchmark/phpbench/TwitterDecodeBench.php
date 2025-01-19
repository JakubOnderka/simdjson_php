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
class TwitterDecodeBench
{

    /**
     * @var string
     */
    private $json;

    public function init(): void
    {
        $this->json = file_get_contents(__DIR__ . '/../../jsonexamples/twitter.json');
    }

    /**
     * @Subject()
     */
    public function jsonDecodeAssoc(): void
    {
        json_decode($this->json, true);
    }

    /**
     * @Subject()
     */
    public function jsonDecode(): void
    {
        json_decode($this->json, false);
    }

    /**
     * @Subject()
     */
    public function jsonValidate(): void
    {
        json_validate($this->json);
    }

    /**
     * @Subject()
     */
    public function jsonKeyCount(): void
    {
        count(json_decode($this->json, true)["statuses"]);
    }

    /**
     * @Subject()
     */
    public function simdjsonDecodeAssoc(): void
    {
        \simdjson_decode($this->json, true);
    }

    /**
     * @Subject()
     */
    public function simdjsonDecode(): void
    {
        \simdjson_decode($this->json, false);
    }

    /**
     * @Subject()
     */
    public function simdjsonValidate(): void
    {
        \simdjson_validate($this->json);
    }

    /**
     * @Subject()
     */
    public function simdjsonKeyCount(): void
    {
        \simdjson_key_count($this->json, "/statuses");
    }
}
