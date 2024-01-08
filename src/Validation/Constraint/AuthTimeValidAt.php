<?php

namespace Beste\Firebase\JWT\Validation\Constraint;

use DateInterval;
use DateTimeImmutable;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\LeewayCannotBeNegative;
use Lcobucci\JWT\Validation\ConstraintViolation;
use Lcobucci\JWT\Validation\ValidAt;
use Psr\Clock\ClockInterface as Clock;

final class AuthTimeValidAt implements ValidAt
{
    private const MICROSECOND_PRECISION = 6;

    private readonly DateInterval $leeway;

    public function __construct(private readonly Clock $clock, ?DateInterval $leeway = null)
    {
        $this->leeway = $this->guardLeeway($leeway);
    }

    private function guardLeeway(?DateInterval $leeway): DateInterval
    {
        if ($leeway === null) {
            return new DateInterval('PT0S');
        }

        if ($leeway->invert === 1) {
            throw LeewayCannotBeNegative::create();
        }

        return $leeway;
    }

    public function assert(Token $token): void
    {
        if (!($token instanceof UnencryptedToken)) {
            throw ConstraintViolation::error('You should pass a plain token', $this);
        }

        if (!$token->claims()->has('auth_time')) {
            throw ConstraintViolation::error('`auth_time` claim missing', $this);
        }

        $now = $this->clock->now();

        $authTime = $token->claims()->get('auth_time');

        if (! is_numeric($authTime)) {
            throw ConstraintViolation::error('`auth_time` claim is not parseable', $this);
        }

        $normalizedTimestamp = number_format((float) $authTime, self::MICROSECOND_PRECISION, '.', '');

        $date = DateTimeImmutable::createFromFormat('U.u', $normalizedTimestamp);

        if ($date === false) {
            throw ConstraintViolation::error('`auth_time` claim is not parseable', $this);
        }

        if (!($now->add($this->leeway) >= $date)) {
            throw ConstraintViolation::error('The token was authenticated in the future', $this);
        }
    }
}
