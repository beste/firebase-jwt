<?php

declare(strict_types=1);

namespace Beste\Firebase\JWT\Validation\Constraint;

use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Beste\Firebase\JWT\Signer\KeyNotFound;
use Beste\Firebase\JWT\Signer\KeySet;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolation;

final readonly class SignedWithOneInKeySet implements Constraint
{
    public function __construct(private KeySet $keySet, private Signer $signer) {}

    public function assert(Token $token): void
    {
        if (!($token instanceof UnencryptedToken)) {
            throw ConstraintViolation::error('You should pass a plain token', $this);
        }

        if (!$token->headers()->has('kid')) {
            throw ConstraintViolation::error('`kid` header missing', $this);
        }

        $keyId = $token->headers()->get('kid');

        if (!is_string($keyId) || $keyId === '') {
            throw ConstraintViolation::error('`kid` header must be a non-empty string', $this);
        }

        try {
            $key = $this->keySet->findKeyById($keyId);
        } catch (KeyNotFound) {
            throw ConstraintViolation::error('Unknown key ID', $this);
        }


        (new SignedWith($this->signer, $key))->assert($token);
    }
}
