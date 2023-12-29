<?php

namespace Beste\Firebase\JWT\Environment;

interface Variables
{
    /**
     * @return non-empty-string
     */
    public function projectId(): string;

    /**
     * @return non-empty-string
     */
    public function clientEmail(): string;

    /**
     * @return non-empty-string
     */
    public function privateKey(): string;
}
