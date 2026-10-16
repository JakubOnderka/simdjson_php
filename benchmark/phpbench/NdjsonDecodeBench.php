<?php

declare(strict_types=1);

namespace SimdjsonBench;

use PhpBench\Benchmark\Metadata\Annotations\Subject;

if (!extension_loaded('simdjson')) {
    exit;
}

/**
 * @Revs(3)
 * @Iterations(5)
 * @Warmup(2)
 * @OutputTimeUnit("milliseconds", precision=5)
 * @BeforeMethods({"init"})
 * @Groups({"ndjson"})
 */
class NdjsonDecodeBench
{
    private const RECORD_COUNT = 1024;
    private const RECORD_SIZE = 1024;

    private string $ndjson;

    public function init(): void
    {
        $path = sys_get_temp_dir() . '/simdjson-phpbench-ecs-' . getmypid() . '.ndjson';
        $expectedSize = self::RECORD_COUNT * self::RECORD_SIZE;

        if (!is_file($path) || filesize($path) !== $expectedSize) {
            $this->generateFixture($path);
        }

        $ndjson = file_get_contents($path);
        if ($ndjson === false) {
            throw new \RuntimeException('Unable to read the ECS NDJSON benchmark fixture');
        }

        $this->ndjson = $ndjson;
    }

    /**
     * @Subject()
     */
    public function simdjsonDecodeIterate(): void
    {
        $count = 0;
        foreach (\simdjson_decode_iterate($this->ndjson) as $record) {
            $count++;
        }

        if ($count !== self::RECORD_COUNT) {
            throw new \RuntimeException(sprintf('Expected %d records, got %d', self::RECORD_COUNT, $count));
        }
    }

    /**
     * @Subject()
     */
    public function jsonDecodeAfterExplode(): void
    {
        $count = 0;
        foreach (explode("\n", $this->ndjson) as $line) {
            if ($line === '') {
                continue;
            }

            json_decode($line, false, 512, JSON_THROW_ON_ERROR);
            $count++;
        }

        if ($count !== self::RECORD_COUNT) {
            throw new \RuntimeException(sprintf('Expected %d records, got %d', self::RECORD_COUNT, $count));
        }
    }

    private function generateFixture(string $path): void
    {
        $handle = fopen($path, 'wb');
        if ($handle === false) {
            throw new \RuntimeException('Unable to create the ECS NDJSON benchmark fixture');
        }

        try {
            for ($i = 0; $i < self::RECORD_COUNT; $i++) {
                $record = [
                    '@timestamp' => sprintf('2025-03-08T12:%02d:%02d.%03dZ', intdiv($i, 60) % 60, $i % 60, $i % 1000),
                    'ecs' => ['version' => '8.17.0'],
                    'event' => ['dataset' => 'api.access', 'duration' => 18342000 + $i],
                    'host' => ['name' => 'api-prod-' . ($i % 16), 'ip' => '192.0.2.' . ($i % 254 + 1)],
                    'log' => ['level' => 'info'],
                    'message' => '',
                    'process' => ['pid' => 2481 + $i % 8],
                    'service' => ['name' => 'checkout-api'],
                ];

                $baseLine = json_encode($record, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
                $record['message'] = 'HTTP request completed ' . str_repeat(
                    'x',
                    self::RECORD_SIZE - 1 - strlen($baseLine) - strlen('HTTP request completed ')
                );
                $line = json_encode($record, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

                if (strlen($line) !== self::RECORD_SIZE - 1 || fwrite($handle, $line . "\n") !== self::RECORD_SIZE) {
                    throw new \RuntimeException('Generated ECS record does not match the expected 1,024-byte line size');
                }
            }
        } finally {
            fclose($handle);
        }
    }
}
