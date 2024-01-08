<?php

namespace Beste\Firebase\JWT\Tests\Token;

use Beste\Cache\InMemoryCache;
use Beste\Clock\FrozenClock;
use Beste\Clock\SystemClock;
use Beste\Firebase\JWT\Signer\CertUrl;
use Beste\Firebase\JWT\Signer\GooglePublicKeys;
use Beste\Firebase\JWT\Tests\TestCase;
use Beste\Firebase\JWT\Token\SecureSessionTokenVerifier;
use Http\Discovery\Psr17FactoryDiscovery;
use Http\Discovery\Psr18ClientDiscovery;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use PHPUnit\Framework\Attributes\DoesNotPerformAssertions;
use Psr\Clock\ClockInterface;

/**
 * @internal
 * @covers \Beste\Firebase\JWT\Token\SecureSessionTokenVerifier
 */
final class SecureSessionTokenVerifierTest extends TestCase
{
    public function testItAcceptsASessionToken(): void
    {
        $customToken = self::customTokenBuilder()->forUser($uid = 'uid')->getToken();
        $sessionCookie = self::customTokenExchanger()->exchangeCustomTokenForSessionCookie($customToken);

        $verified = $this->verifier()->verify($sessionCookie);

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
            ->getToken();

        $sessionCookie = self::customTokenExchanger()->exchangeCustomTokenForSessionCookie(
            customToken: $customToken,
            tenantId: $tenantId,
        );

        $this->verifier()
            ->withExpectedTenantId($tenantId)
            ->verify($sessionCookie);
    }

    public function testItRejectsAnInvalidAuthTime(): void
    {
        $customToken = self::customTokenBuilder()
            ->forUser('uid')
            ->expiresAfter(new \DateInterval('PT10M'))
            ->getToken();

        $sessionCookie = self::customTokenExchanger()->exchangeCustomTokenForSessionCookie($customToken);

        // Since the idToken is real, we have to set our verifier with a clock in the past
        $pastClock = FrozenClock::at(SystemClock::create()->now()->modify('-1 hour'));

        // It is one hour later, but the token expired after 10 Minutes
        $this->expectException(RequiredConstraintsViolated::class);
        $this->verifier($pastClock)->verify($sessionCookie);
    }

    #[DoesNotPerformAssertions]
    public function testItAcceptsAnExpiredIdTokenWithLeeway(): void
    {
        $correctClock = SystemClock::create();
        $futureClock = FrozenClock::fromUTC();
        $futureClock->setTo($futureClock->now()->modify('+1 hour'));

        $customToken = self::customTokenBuilder($correctClock)
            ->forUser('uid')
            ->getToken();

        $sessionCookie = self::customTokenExchanger()->exchangeCustomTokenForSessionCookie(
            customToken: $customToken,
            idTokenExpiresAfter: new \DateInterval('PT10M'),
        );

        // It is one hour later, but the token expired after 10 minutes, so 50 minutes ago
        $this->verifier($futureClock)
            ->withLeeway(new \DateInterval('PT51M'))
            ->verify($sessionCookie);
    }

    private function verifier(?ClockInterface $clock = null): SecureSessionTokenVerifier
    {
        $clock ??= SystemClock::create();

        return new SecureSessionTokenVerifier(
            projectId: self::variables()->projectId(),
            clock: $clock,
            keySet: new GooglePublicKeys(
                CertUrl::forSessionCookieVerification(),
                Psr18ClientDiscovery::find(),
                Psr17FactoryDiscovery::findRequestFactory(),
                new InMemoryCache($clock),
            )
        );
    }
}
