<?php

namespace Beste\Firebase\JWT\Tests\Support;

use Beste\Firebase\JWT\Signer\KeyNotFound;
use Beste\Firebase\JWT\Signer\KeySet;
use Lcobucci\JWT\Signer\Key;

/**
 * @internal
 */
final class InMemoryKeySet implements KeySet
{
    private int $invocations = 0;

    /**
     * @param array<non-empty-string, Key> $keys
     */
    public function __construct(private array $keys = []) {}

    public function findKeyById(string $id): Key
    {
        ++$this->invocations;

        if (!array_key_exists($id, $this->keys)) {
            throw KeyNotFound::unknownKeyID($id);
        }

        return $this->keys[$id];
    }
}
