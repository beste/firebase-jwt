<?php

namespace Beste\Firebase\JWT\Validation\Constraint;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolation;

final class HasTenant implements Constraint
{
    public function __construct(private readonly string $tenantId) {}

    public function assert(Token $token): void
    {
        if (!($token instanceof UnencryptedToken)) {
            throw ConstraintViolation::error('You should pass a plain token', $this);
        }

        if (!$token->claims()->has('firebase')) {
            throw ConstraintViolation::error('`firebase` claim missing', $this);
        }

        $claims = $token->claims()->get('firebase');

        if (!is_array($claims)) {
            throw ConstraintViolation::error('`firebase` claim is not an array/map', $this);
        }

        if (!array_key_exists('tenant', $claims)) {
            throw ConstraintViolation::error('`firebase.tenant` claim missing', $this);
        }

        if ($claims['tenant'] !== $this->tenantId) {
            throw ConstraintViolation::error('`firebase.tenant` claim does not match expected value', $this);
        }
    }
}
