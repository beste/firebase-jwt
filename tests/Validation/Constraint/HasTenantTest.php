<?php

namespace Beste\Firebase\JWT\Tests\Validation\Constraint;

use Beste\Firebase\JWT\Tests\TestCase;
use Beste\Firebase\JWT\Validation\Constraint\HasTenant;
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
 * @internal
 *
 * @covers \Beste\Firebase\JWT\Validation\Constraint\HasTenant
 */
final class HasTenantTest extends TestCase
{
    private InMemory $privateKey;
    private HasTenant $constraint;

    protected function setUp(): void
    {
        $this->privateKey = InMemory::file(__DIR__ . '/../../_fixtures/private.key');
        $this->constraint = new HasTenant('tenantId');
    }

    #[DoesNotPerformAssertions]
    public function testItExpectsAToken(): void
    {
        $token = $this->token(['firebase' => ['tenant' => 'tenantId']]);

        $this->constraint->assert($token);
    }

    public function testItRejectsAMismatchingTenant(): void
    {
        $token = $this->token(['firebase' => ['tenant' => 'otherTenantId']]);

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessageMatches('/does not match/');

        $this->constraint->assert($token);
    }

    public function testItRejectsNotUnencryptedTokens(): void
    {
        $token = $this->createMock(Token::class);

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessageMatches('/should pass/');

        $this->constraint->assert($token);
    }

    public function testItRejectsTokensWithoutAFirebaseClaim(): void
    {
        $token = $this->token([]);

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessageMatches('/firebase.+claim.+missing/');

        $this->constraint->assert($token);
    }

    public function testIRejectsAnInvalidFirebaseClaim(): void
    {
        $token = $this->token(['firebase' => 'a string is not an object']);

        $this->expectExceptionMessageMatches('/not an array/');

        $this->constraint->assert($token);
    }

    public function testItRejectsAMissingTenantClaim(): void
    {
        $token = $this->token(['firebase' => []]);

        $this->expectExceptionMessageMatches('/tenant.+claim.+missing/');

        $this->constraint->assert($token);
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
