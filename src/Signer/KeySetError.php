<?php

namespace Beste\Firebase\JWT\Signer;

use Beste\Firebase\JWT\Exception;

final class KeySetError extends \RuntimeException implements Exception
{
    public static function withReason(string $error): self
    {
        return new self('The key set is invalid:' . $error);
    }
}
