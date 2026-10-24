<?php
declare(strict_types=1);
header('Content-Type: application/json');

function same($a, $b): bool { return serialize($a) === serialize($b); }

try {
  if (!extension_loaded('simdjson')) {
      throw new RuntimeException('simdjson not loaded');
  }

  $mode = $_GET['mode'] ?? 'direct';
  $raw = null;

  if ($mode === 'pre-read') {
      $raw = file_get_contents('php://input');
  }

  $inputErr = null;
  try {
      $fromInput = simdjson_decode_from_input(true);
  } catch (SimdJsonDecoderException $e) {
      $fromInput = null;
      $inputErr = $e;
  }

  if ($raw === null) {
      $raw = file_get_contents('php://input');
  }

  try {
      $native = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
      $valid = true;
  } catch (JsonException $e) {
      $native = null;
      $valid = false;
  }

  if (!$valid) {
      if ($inputErr === null) {
          throw new RuntimeException('decode_from_input accepted invalid JSON');
      }
      $rejected = false;
      try { simdjson_decode($raw, true); } catch (SimdJsonDecoderException $e) { $rejected = true; }
      if (!$rejected) {
          throw new RuntimeException('simdjson_decode accepted invalid JSON');
      }
      http_response_code(422);
      echo json_encode(['ok' => true, 'rejected' => true, 'pid' => getmypid(), 'hash' => hash('sha256', $raw)]);
      exit;
  }

  if ($inputErr !== null) {
      throw new RuntimeException('decode_from_input rejected valid JSON');
  }
  if (!same($fromInput, $native)) {
      throw new RuntimeException('first decode mismatch');
  }

  foreach ([true, false] as $assoc) {
      $expected = json_decode($raw, $assoc, 512, JSON_THROW_ON_ERROR);
      for ($i = 0; $i < 3; $i++) {
          $a = simdjson_decode_from_input($assoc);
          $b = simdjson_decode($raw, $assoc);
          if (!same($a, $expected) || !same($b, $expected)) {
              throw new RuntimeException('repeat decode mismatch');
          }
          foreach ([0, SIMDJSON_PRETTY_PRINT, SIMDJSON_APPEND_NEWLINE] as $flags) {
              $enc = simdjson_encode($b, $flags);
              $round = json_decode($enc, $assoc, 512, JSON_THROW_ON_ERROR);
              if (!same($round, $expected)) {
                  throw new RuntimeException('encode roundtrip mismatch');
              }
          }
      }
  }

  $nanRejected = false;
  try { simdjson_encode(NAN); } catch (SimdJsonEncoderException $e) { $nanRejected = true; }
  if (!$nanRejected) {
      throw new RuntimeException('NAN was accepted by simdjson_encode');
  }

  echo json_encode(['ok' => true, 'pid' => getmypid(), 'hash' => hash('sha256', $raw), 'value' => $fromInput]);
} catch (Throwable $e) {
  http_response_code(500);
  echo json_encode(['ok' => false, 'error' => $e->getMessage()]);
}
