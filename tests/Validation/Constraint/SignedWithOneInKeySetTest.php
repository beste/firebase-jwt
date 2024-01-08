<?php

namespace Beste\Firebase\JWT\Tests\Validation\Constraint;

use Beste\Firebase\JWT\Tests\Support\InMemoryKeySet;
use Beste\Firebase\JWT\Tests\TestCase;
use Beste\Firebase\JWT\Validation\Constraint\SignedWithOneInKeySet;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\Builder;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\ConstraintViolation;
use PHPUnit\Framework\Attributes\DoesNotPerformAssertions;

/**
 * @covers \Beste\Firebase\JWT\Validation\Constraint\SignedWithOneInKeySet
 * @internal
 */
final class SignedWithOneInKeySetTest extends TestCase
{
    private InMemory $privateKey;
    private SignedWithOneInKeySet $constraint;
    private InMemory $publicKey;

    protected function setUp(): void
    {
        $this->privateKey = InMemory::file(__DIR__ . '/../../_fixtures/private.key');
        $this->publicKey = InMemory::file(__DIR__ . '/../../_fixtures/public.key');

        $keySet = new InMemoryKeySet(['kid' => $this->publicKey]);
        $this->constraint = new SignedWithOneInKeySet($keySet, new Sha256());
    }

    #[DoesNotPerformAssertions]
    public function testItAcceptsAnExpectedToken(): void
    {
        $token = $this->token(headers: ['kid' => 'kid']);

        $this->constraint->assert($token);
    }

    public function testItExpectsAnUnencryptedToken(): void
    {
        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessageMatches('/should pass/i');

        $this->constraint->assert($this->createMock(Token::class));
    }

    public function testItExpectsAKnownKeyId(): void
    {
        $token = $this->token(headers: ['kid' => 'unknown']);

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessageMatches('/unknown.+key.+id/i');

        $this->constraint->assert($token);
    }

    public function testItExpectsAKidHeader(): void
    {
        $token = $this->token([]);

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessageMatches('/kid.+missing/i');

        $this->constraint->assert($token);
    }

    public function testItExpectsANonEmptyKidHeader(): void
    {
        $token = $this->token(['kid' => '']);

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessageMatches('/non-empty string/i');

        $this->constraint->assert($token);
    }

    public function testItExpectsAStringForTheKidHeader(): void
    {
        $token = $this->token(['kid' => 1]);

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessageMatches('/non-empty string/i');

        $this->constraint->assert($token);
    }

    /**
     * @param array<non-empty-string, mixed> $headers
     * @param array<non-empty-string, mixed> $claims
     */
    private function token(array $headers, array $claims = []): UnencryptedToken
    {
        $builder = new Builder(new JoseEncoder(), ChainedFormatter::withUnixTimestampDates());

        foreach ($headers as $name => $value) {
            $builder = $builder->withHeader($name, $value);
        }

        foreach ($claims as $name => $value) {
            $builder = $builder->withClaim($name, $value);
        }

        return $builder->getToken(new Sha256(), $this->privateKey);
    }
}
