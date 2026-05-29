<?php

declare(strict_types=1);

namespace Beste\Firebase\JWT\Signer;

use Lcobucci\JWT\Signer\Key;

interface KeySet
{
    /**
     * @param non-empty-string $id
     *
     * @throws KeySetError
     */
    public function addKey(string $id, Key $key): void;

    /**
     * @param non-empty-string $id
     *
     * @throws KeyNotFound
     * @throws KeySetError
     */
    public function findKeyById(string $id): Key;
}
