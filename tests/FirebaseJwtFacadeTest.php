<?php

namespace Beste\Firebase\JWT\Tests;

use Beste\Clock\FrozenClock;
use Beste\Firebase\JWT\FirebaseJwtFacade;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use PHPUnit\Framework\Attributes\DoesNotPerformAssertions;

/**
 * @covers \Beste\Firebase\JWT\FirebaseJwtFacade
 * @covers \Beste\Firebase\JWT\Signer\CertUrl
 * @internal
 */
final class FirebaseJwtFacadeTest extends \Beste\Firebase\JWT\Tests\TestCase
{
    protected Signer $signer;
    protected FirebaseJwtFacade $facade;

    protected function setUp(): void
    {
        $this->signer = new Sha256();

        $this->facade = FirebaseJwtFacade::createFromEnvironment();
    }

    public function testItIssuesACustomToken(): void
    {
        $token = $this->facade->issueCustomToken(uid: 'uid', customClaims: ['custom' => 'claim']);

        $parsed = (new Parser(new JoseEncoder()))->parse($token->toString());
        assert($parsed instanceof UnencryptedToken);

        $claims = $parsed->claims();

        self::assertSame($token->toString(), $parsed->toString());
        self::assertSame('uid', $claims->get('uid'));
        self::assertIsArray($claims->get('claims'));
        self::assertSame('claim', $claims->get('claims')['custom']);
    }

    public function testItIssuesACustomTokenIncludingATenant(): void
    {
        $token = $this->facade->issueCustomToken(uid: 'uid', tenantId: 'tenant');

        $parsed = (new Parser(new JoseEncoder()))->parse($token->toString());
        assert($parsed instanceof UnencryptedToken);

        $claims = $parsed->claims();

        self::assertSame($token->toString(), $parsed->toString());
        self::assertSame('uid', $claims->get('uid'));
        self::assertSame('tenant', $claims->get('tenant_id'));
    }

    public function testItVerifiesAnIdToken(): void
    {
        $customToken = self::customTokenBuilder()
            ->forUser('github-supporter')
            ->forTenant(self::tenantId())
            ->withCustomClaim('is_awesome', true)
            ->withCustomClaim('perks', $perks = [
                'badges' => ['premium_user', 'github_supporter'],
                'support_tier' => 'individual_support',
            ])
            ->withCustomClaim('level', 1)
            ->getToken()
        ;

        $idToken = self::customTokenExchanger()->exchangeCustomTokenForIdToken($customToken);

        $idToken = $this->facade->verifyIdToken($idToken);

        self::assertSame('github-supporter', $idToken->claims()->get('user_id'));
        self::assertSame('github-supporter', $idToken->claims()->get('sub'));
        self::assertTrue($idToken->claims()->get('is_awesome'));
        self::assertEqualsCanonicalizing($perks, $idToken->claims()->get('perks'));
        self::assertSame(1, $idToken->claims()->get('level'));
        self::assertTrue($idToken->claims()->has('firebase'));

        $firebaseClaims = $idToken->claims()->get('firebase');
        self::assertIsArray($firebaseClaims);

        self::assertSame(self::tenantId(), $firebaseClaims['tenant']);
        self::assertSame('custom', $firebaseClaims['sign_in_provider']);
    }

    #[DoesNotPerformAssertions]
    public function testItVerifiesAnIdTokenWithATenantId(): void
    {
        $tenantId = self::tenantId();

        $customToken = self::customTokenBuilder()->forUser('uid')->forTenant($tenantId)->getToken();
        $idToken = self::customTokenExchanger()->exchangeCustomTokenForIdToken($customToken);

        $this->facade->verifyIdToken($idToken, $tenantId);
    }

    public function testItRejectsAnExpiredIdToken(): void
    {
        $clock = FrozenClock::fromUTC();

        $customToken = self::customTokenBuilder()
            ->forUser('uid')
            ->expiresAfter(new \DateInterval('PT10M'))
            ->getToken()
        ;

        $idToken = self::customTokenExchanger()->exchangeCustomTokenForIdToken($customToken);

        $facade = new FirebaseJwtFacade(
            variables: self::variables(),
            clock: FrozenClock::at($clock->now()->modify('-1 minute')),
        );

        $this->expectException(RequiredConstraintsViolated::class);
        $this->expectExceptionMessageMatches('/future/');

        $facade->verifyIdToken(jwt: $idToken);
    }

    #[DoesNotPerformAssertions]
    public function testItAcceptsAnExpiredIdTokenWithLeeway(): void
    {
        $clock = FrozenClock::fromUTC();

        $customToken = self::customTokenBuilder()
            ->forUser('uid')
            ->expiresAfter(new \DateInterval('PT10M'))
            ->getToken()
        ;

        $idToken = self::customTokenExchanger()->exchangeCustomTokenForIdToken($customToken);

        $facade = new FirebaseJwtFacade(
            variables: self::variables(),
            clock: FrozenClock::at($clock->now()->modify('-10 minutes')),
        );

        $facade->verifyIdToken(jwt: $idToken, leeway: new \DateInterval('PT11M'));
    }

    #[DoesNotPerformAssertions]
    public function testItVerifiesASessionCookie(): void
    {
        $customToken = self::customTokenBuilder()->forUser('uid')->getToken();
        $sessionCookie = self::customTokenExchanger()->exchangeCustomTokenForSessionCookie($customToken);

        $this->facade->verifySessionCookie($sessionCookie);
    }

    #[DoesNotPerformAssertions]
    public function testItVerifiesASessionCookieWithATenantId(): void
    {
        $tenantId = self::tenantId();

        $customToken = self::customTokenBuilder()->forUser('uid')->forTenant($tenantId)->getToken();
        $sessionCookie = self::customTokenExchanger()->exchangeCustomTokenForSessionCookie($customToken);

        $this->facade->verifySessionCookie($sessionCookie, $tenantId);
    }

    public function testItRejectsAnExpiredSessionCookie(): void
    {
        $customToken = self::customTokenBuilder()->forUser('uid')->getToken();
        $sessionCookie = self::customTokenExchanger()->exchangeCustomTokenForSessionCookie(
            customToken: $customToken,
            idTokenExpiresAfter: new \DateInterval('PT10M'),
        );

        $clock = FrozenClock::fromUTC();

        $facade = new FirebaseJwtFacade(
            variables: self::variables(),
            clock: FrozenClock::at($clock->now()->modify('-1 minutes')),
        );

        $this->expectException(RequiredConstraintsViolated::class);
        $this->expectExceptionMessageMatches('/future/');

        $facade->verifySessionCookie(jwt: $sessionCookie);
    }

    #[DoesNotPerformAssertions]
    public function testItAcceptsAnExpiredSessionCookieWithLeeway(): void
    {
        $clock = FrozenClock::fromUTC();

        $customToken = self::customTokenBuilder()->forUser('uid')->getToken();
        $sessionCookie = self::customTokenExchanger()->exchangeCustomTokenForSessionCookie(
            customToken: $customToken,
            idTokenExpiresAfter: new \DateInterval('PT10M'),
        );

        $facade = new FirebaseJwtFacade(
            variables: self::variables(),
            clock: FrozenClock::at($clock->now()->modify('-10 minutes')),
        );

        $facade->verifySessionCookie(jwt: $sessionCookie, leeway: new \DateInterval('PT11M'));
    }
}
