<?php

namespace Beste\Firebase\JWT\Signer;

use Lcobucci\JWT\Signer\Key;

interface KeySet
{
    /**
     * @param non-empty-string $id
     *
     * @throws KeyNotFound
     * @throws KeySetError
     */
    public function findKeyById(string $id): Key;
}
