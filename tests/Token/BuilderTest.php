<?php

namespace Beste\Firebase\JWT\Tests\Token;

use Beste\Clock\FrozenClock;
use Beste\Firebase\JWT\Tests\TestCase;
use Beste\Firebase\JWT\Token\Builder;
use Lcobucci\JWT\JwtFacade;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\RelatedTo;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use PHPUnit\Framework\Attributes\DoesNotPerformAssertions;

/**
 * @covers \Beste\Firebase\JWT\Token\Builder
 * @internal
 */
final class BuilderTest extends TestCase
{
    private FrozenClock $clock;
    private InMemory $privateKey;
    private InMemory $publicKey;
    /** @var non-empty-string */
    private string $clientEmail;

    protected function setUp(): void
    {
        $this->clock = FrozenClock::fromUTC();
        $this->privateKey = InMemory::file(__DIR__ . '/../_fixtures/private.key');
        $this->publicKey = InMemory::file(__DIR__ . '/../_fixtures/public.key');
        $this->clientEmail = 'client@example.com';
    }

    #[DoesNotPerformAssertions]
    public function testItFulfillsTheConstraints(): void
    {
        $token = $this->builder()->getToken();

        $this->parse(
            $token,
            new RelatedTo($this->clientEmail),
            new IssuedBy($this->clientEmail),
        );
    }

    #[DoesNotPerformAssertions]
    public function testItIsIssuedByAndRelatedToTheGivenClientEmail(): void
    {
        $token = $this->builder()->getToken();

        $this->parse(
            $token,
            new RelatedTo($this->clientEmail),
            new IssuedBy($this->clientEmail),
        );
    }

    #[DoesNotPerformAssertions]
    public function testItIsIssuedToAUid(): void
    {
        $token = $this->builder(uid: __FUNCTION__, )->getToken();

        $this->parse(
            $token,
            new Constraint\HasClaimWithValue('uid', __FUNCTION__),
        );
    }

    public function testItCanOnlyBeUsedAfterTheGivenDuration(): void
    {
        $expiresAfter = new \DateInterval('PT1337M');
        $now = $this->clock->now();
        $expiresAt = $now->add($expiresAfter);

        $token = $this->builder()
            ->expiresAfter($expiresAfter)
            ->getToken();

        $parsed = $this->parse($token);
        $claims = $parsed->claims();
        $expiration = $claims->get(Token\RegisteredClaims::EXPIRATION_TIME);
        assert($expiration instanceof \DateTimeImmutable);

        self::assertSame($expiresAt->format('U'), $expiration->format('U'));
    }

    public function testItIsRsa256Encoded(): void
    {
        $token = $this->builder()->getToken();

        $parsedToken = $this->parse($token);

        self::assertSame((new Sha256())->algorithmId(), $parsedToken->headers()->get('alg'));
    }

    #[DoesNotPerformAssertions]
    public function testItAcceptsClaims(): void
    {
        $token = $this->builder()->withClaim('name', 'value')->getToken();

        $this->parse(
            $token,
            new Constraint\HasClaimWithValue('name', 'value'),
        );
    }

    #[DoesNotPerformAssertions]
    public function testItAcceptsATenantId(): void
    {
        $tenantId = self::tenantId();

        $token = $this->builder()->forTenant($tenantId)->getToken();

        $this->parse(
            $token,
            new Constraint\HasClaimWithValue('tenant_id', $tenantId),
        );
    }

    #[DoesNotPerformAssertions]
    public function testItAcceptsCustomClaims(): void
    {
        $token = $this->builder()->withCustomClaim('claim', 'value')->getToken();

        $this->parse(
            $token,
            new Constraint\HasClaimWithValue('claims', ['claim' => 'value']),
        );
    }

    private function parse(Token $token, Constraint ...$constraints): UnencryptedToken
    {
        $signedWith = new SignedWith(new Sha256(), $this->publicKey);
        $validAt = new StrictValidAt($this->clock);

        return (new JwtFacade())->parse($token->toString(), $signedWith, $validAt, ...$constraints);
    }

    /**
     * @param non-empty-string|null $uid
     */
    private function builder(?string $uid = null): \Beste\Firebase\JWT\Builder
    {
        $uid ??= 'uid';

        return (new Builder(
            clientEmail: $this->clientEmail,
            privateKey: $this->privateKey->contents(),
            clock: $this->clock,
        ))->forUser($uid);
    }
}
