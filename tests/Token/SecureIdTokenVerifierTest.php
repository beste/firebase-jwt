<?php

namespace Beste\Firebase\JWT\Tests\Token;

use Beste\Cache\InMemoryCache;
use Beste\Clock\FrozenClock;
use Beste\Clock\SystemClock;
use Beste\Firebase\JWT\Builder as BuilderInterface;
use Beste\Firebase\JWT\IdTokenVerifier;
use Beste\Firebase\JWT\Signer\GooglePublicKeys;
use Beste\Firebase\JWT\Tests\TestCase;
use Beste\Firebase\JWT\Token\Builder;
use Beste\Firebase\JWT\Token\SecureIdTokenVerifier;
use Http\Discovery\Psr17FactoryDiscovery;
use Http\Discovery\Psr18ClientDiscovery;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use PHPUnit\Framework\Attributes\DoesNotPerformAssertions;
use Psr\Clock\ClockInterface;

/**
 * @covers \Beste\Firebase\JWT\Token\SecureIdTokenVerifier
 * @internal
 */
final class SecureIdTokenVerifierTest extends TestCase
{
    public function testItVerifiesAValidIdToken(): void
    {
        $uid = 'uid';
        $customToken = $this->builder()->relatedToUser($uid)->getToken();

        $idToken = self::customTokenExchanger()
            ->exchangeCustomTokenForIdToken($customToken);

        $verified = $this->verifier()->verify($idToken);

        self::assertTrue($verified->isRelatedTo($uid));
        self::assertSame($uid, $verified->claims()->get('user_id'));
    }

    #[DoesNotPerformAssertions]
    public function testItVerifiesATenant(): void
    {
        $tenantId = self::tenantId();

        $customToken = $this->builder()
            ->relatedToUser('uid')
            ->relatedToTenant($tenantId)
            ->getToken();

        $idToken = self::customTokenExchanger()->exchangeCustomTokenForIdToken($customToken);

        $this->verifier()
            ->withExpectedTenantId($tenantId)
            ->verify($idToken);
    }

    public function testItRejectsAnExpiredIdToken(): void
    {
        $customToken = $this->builder()
            ->relatedToUser('uid')
            ->expiresAfter(new \DateInterval('PT10M'))
            ->getToken();

        $idToken = self::customTokenExchanger()->exchangeCustomTokenForIdToken($customToken);

        // Since the idToken is real, we have to set our verifier with a clock in the past
        $pastClock = FrozenClock::at(SystemClock::create()->now()->modify('-1 hour'));

        // It is one hour later, but the token expired after 10 Minutes
        $this->expectException(RequiredConstraintsViolated::class);
        $this->verifier($pastClock)->verify($idToken);
    }

    #[DoesNotPerformAssertions]
    public function testItAcceptsAnExpiredIdTokenWithLeeway(): void
    {
        $correctClock = SystemClock::create();
        $futureClock = FrozenClock::fromUTC();
        $futureClock->setTo($futureClock->now()->modify('+1 hour'));

        $customToken = $this->builder($correctClock)
            ->relatedToUser('uid')
            ->expiresAfter(new \DateInterval('PT10M'))
            ->getToken();

        $idToken = self::customTokenExchanger()->exchangeCustomTokenForIdToken($customToken);

        // It is one hour later, but the token expired after 10 Minutes
        $this->verifier($futureClock)
            ->withLeeway(new \DateInterval('PT51M'))
            ->verify($idToken);
    }

    private function builder(?ClockInterface $clock = null): BuilderInterface
    {
        $clock ??= SystemClock::create();

        return (new Builder(
            clientEmail: self::variables()->clientEmail(),
            privateKey: self::variables()->privateKey(),
            clock: $clock,
        ));
    }

    private function verifier(?ClockInterface $clock = null): IdTokenVerifier
    {
        $clock ??= SystemClock::create();

        return new SecureIdTokenVerifier(
            projectId: self::variables()->projectId(),
            clock: $clock,
            keySet: new GooglePublicKeys(
                Psr18ClientDiscovery::find(),
                Psr17FactoryDiscovery::findRequestFactory(),
                new InMemoryCache($clock),
            )
        );
    }
}
