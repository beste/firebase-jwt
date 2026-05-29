<?php

declare(strict_types=1);

namespace Beste\Firebase\JWT\Tests\Support;

use Beste\Firebase\JWT\Signer\KeyNotFound;
use Beste\Firebase\JWT\Signer\KeySet;
use Lcobucci\JWT\Signer\Key;

/**
 * @internal
 */
final class InMemoryKeySet implements KeySet
{
    /**
     * @param array<non-empty-string, Key> $keys
     */
    public function __construct(private array $keys = []) {}

    public function addKey(string $id, Key $key): void
    {
        $this->keys[$id] = $key;
    }

    public function findKeyById(string $id): Key
    {
        if (!array_key_exists($id, $this->keys)) {
            throw KeyNotFound::unknownKeyID($id);
        }

        return $this->keys[$id];
    }
}
