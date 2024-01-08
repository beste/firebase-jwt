<?php

namespace Beste\Firebase\JWT\Tests\Validation\Constraint;

use Beste\Clock\FrozenClock;
use Beste\Firebase\JWT\Validation\Constraint\AuthTimeValidAt;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\Builder;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\LeewayCannotBeNegative;
use Lcobucci\JWT\Validation\ConstraintViolation;
use PHPUnit\Framework\Attributes\DoesNotPerformAssertions;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 * @covers \Beste\Firebase\JWT\Validation\Constraint\AuthTimeValidAt
 */
final class AuthTimeValidAtTest extends TestCase
{
    private FrozenClock $clock;
    private InMemory $privateKey;
    private AuthTimeValidAt $constraint;

    protected function setUp(): void
    {
        $this->clock = FrozenClock::fromUTC();
        $this->privateKey = InMemory::file(__DIR__ . '/../../_fixtures/private.key');
        $this->constraint = new AuthTimeValidAt($this->clock);
    }

    public function testItExpectsAPositiveLeeway(): void
    {
        $clock = FrozenClock::fromUTC();
        $leeway = $clock->now()->diff($clock->now()->modify('-1 second'));

        $this->expectException(LeewayCannotBeNegative::class);
        new AuthTimeValidAt($clock, $leeway);
    }

    public function testItExpectsAnUnencryptedToken(): void
    {
        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessageMatches('/should.+pass.+token/');

        $this->constraint->assert($this->createMock(Token::class));
    }

    public function testItExpectsAnAuthTimeClaim(): void
    {
        $token = $this->token([]);

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessageMatches('/auth_time.+missing/');

        $this->constraint->assert($token);
    }

    public function testItExpectsANumericTimestampValue(): void
    {
        $token = $this->token(['auth_time' => 'invalid']);

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessageMatches('/auth_time.+not parseable/');

        $this->constraint->assert($token);
    }

    public function testItExpectsTheTimestampToMakeSense(): void
    {
        $token = $this->token(['auth_time' => '99999999999999999999999999999999999']);

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessageMatches('/auth_time.+not parseable/');

        $this->constraint->assert($token);
    }

    public function testItExpectsTheAuthTimeToBeInThePast(): void
    {
        $token = $this->token(['auth_time' => $this->clock->now()->modify('+1 second')->getTimestamp()]);

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessageMatches('/future/');

        $this->constraint->assert($token);
    }

    #[DoesNotPerformAssertions]
    public function testItAcceptsAFutureTokenWithLeeway(): void
    {
        $clock = FrozenClock::fromUTC();
        $constraint = new AuthTimeValidAt($clock, new \DateInterval('PT10S'));

        $token = $this->token(['auth_time' => $clock->now()->getTimestamp()]);

        // Turn the time back 10 seconds, now the token is issued in the future
        $clock->setTo($this->clock->now()->modify('-10 seconds'));

        // With the 10s leeway, it should be okay
        $constraint->assert($token);
    }

    /**
     * @param array<non-empty-string, mixed> $claims
     */
    private function token(array $claims): UnencryptedToken
    {
        $builder = new Builder(new JoseEncoder(), ChainedFormatter::withUnixTimestampDates());

        foreach ($claims as $name => $value) {
            $builder = $builder->withClaim($name, $value);
        }

        return $builder->getToken(new Sha256(), $this->privateKey);
    }
}
