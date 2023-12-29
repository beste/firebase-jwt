<?php

namespace Beste\Firebase\JWT\Signer;

use Beste\Firebase\JWT\Exception;
use RuntimeException;

final class KeyNotFound extends RuntimeException implements Exception
{
    public static function unknownKeyID(string $keyId): self
    {
        return new self("The key set does not contain a key identified by `$keyId`");
    }
}
