<?php

namespace Beste\Firebase\JWT\Tests\Token;

use Beste\Cache\InMemoryCache;
use Beste\Clock\FrozenClock;
use Beste\Clock\SystemClock;
use Beste\Firebase\JWT\Signer\CertUrl;
use Beste\Firebase\JWT\Signer\GooglePublicKeys;
use Beste\Firebase\JWT\Tests\TestCase;
use Beste\Firebase\JWT\Token\SecureIdTokenVerifier;
use Http\Discovery\Psr17FactoryDiscovery;
use Http\Discovery\Psr18ClientDiscovery;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use PHPUnit\Framework\Attributes\DoesNotPerformAssertions;
use Psr\Clock\ClockInterface;

/**
 * @covers \Beste\Firebase\JWT\Token\SecureIdTokenVerifier
 *
 * @internal
 */
final class SecureIdTokenVerifierTest extends TestCase
{
    public function testItVerifiesAValidIdToken(): void
    {
        $customToken = self::customTokenBuilder()->forUser($uid = 'uid')->getToken();

        $idToken = self::customTokenExchanger()
            ->exchangeCustomTokenForIdToken($customToken)
        ;

        $verified = $this->verifier()->verify($idToken);

        self::assertTrue($verified->isRelatedTo($uid));
        self::assertSame($uid, $verified->claims()->get('user_id'));
    }

    #[DoesNotPerformAssertions]
    public function testItVerifiesATenant(): void
    {
        $tenantId = self::tenantId();

        $customToken = self::customTokenBuilder()
            ->forUser('uid')
            ->forTenant($tenantId)
            ->getToken()
        ;

        $idToken = self::customTokenExchanger()->exchangeCustomTokenForIdToken($customToken);

        $this->verifier()
            ->withExpectedTenantId($tenantId)
            ->verify($idToken)
        ;
    }

    public function testItRejectsAnExpiredIdToken(): void
    {
        $customToken = self::customTokenBuilder()
            ->forUser('uid')
            ->expiresAfter(new \DateInterval('PT10M'))
            ->getToken()
        ;

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

        $customToken = self::customTokenBuilder($correctClock)
            ->forUser('uid')
            ->expiresAfter(new \DateInterval('PT10M'))
            ->getToken()
        ;

        $idToken = self::customTokenExchanger()->exchangeCustomTokenForIdToken($customToken);

        // It is one hour later, but the token expired after 10 minutes, so 50 minutes ago
        $this->verifier($futureClock)
            ->withLeeway(new \DateInterval('PT51M'))
            ->verify($idToken)
        ;
    }

    private function verifier(?ClockInterface $clock = null): SecureIdTokenVerifier
    {
        $clock ??= SystemClock::create();

        return new SecureIdTokenVerifier(
            projectId: self::variables()->projectId(),
            clock: $clock,
            keySet: new GooglePublicKeys(
                CertUrl::forIdTokenVerification(),
                Psr18ClientDiscovery::find(),
                Psr17FactoryDiscovery::findRequestFactory(),
                new InMemoryCache($clock),
            ),
        );
    }
}
