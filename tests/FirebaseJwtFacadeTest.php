<?php

namespace Beste\Firebase\JWT\Tests;

use Beste\Clock\FrozenClock;
use Beste\Firebase\JWT\FirebaseJwtFacade;
use Beste\Firebase\JWT\Token\Builder;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use PHPUnit\Framework\Attributes\DoesNotPerformAssertions;

/**
 * @covers \Beste\Firebase\JWT\FirebaseJwtFacade
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

        self::assertSame($token->toString(), $parsed->toString());
    }

    #[DoesNotPerformAssertions]
    public function testItVerifiesAnIdToken(): void
    {
        $customToken = $this->facade->issueCustomToken('uid');
        $idToken = self::customTokenExchanger()->exchangeCustomTokenForIdToken($customToken);

        $this->facade->verifyIdToken($idToken);
    }

    #[DoesNotPerformAssertions]
    public function testItVerifiesAnIdTokenWithATenantId(): void
    {
        $tenantId = self::tenantId();

        $customToken = $this->facade->issueCustomToken(uid: 'uid', tenantId: $tenantId);
        $idToken = self::customTokenExchanger()->exchangeCustomTokenForIdToken($customToken);

        $this->facade->verifyIdToken($idToken, $tenantId);
    }

    public function testItRejectsAnExpiredToken(): void
    {
        $clock = FrozenClock::fromUTC();

        $builder = new Builder(
            clientEmail: self::variables()->clientEmail(),
            privateKey: self::variables()->privateKey(),
            clock: $clock,
        );

        $customToken = $builder
            ->forUser('uid')
            ->expiresAfter(new \DateInterval('PT10M'))
            ->getToken();

        $idToken = self::customTokenExchanger()->exchangeCustomTokenForIdToken($customToken);

        $facade = new FirebaseJwtFacade(
            variables: self::variables(),
            clock: FrozenClock::at($clock->now()->modify('-11 minutes')),
        );

        $this->expectException(RequiredConstraintsViolated::class);
        $this->expectExceptionMessageMatches('/future/');

        $facade->verifyIdToken(jwt: $idToken);
    }

    #[DoesNotPerformAssertions]
    public function testItAcceptsAnExpiredItTokenWithLeeway(): void
    {
        $clock = FrozenClock::fromUTC();

        $builder = new Builder(
            clientEmail: self::variables()->clientEmail(),
            privateKey: self::variables()->privateKey(),
            clock: $clock,
        );

        $customToken = $builder
            ->forUser('uid')
            ->expiresAfter(new \DateInterval('PT10M'))
            ->getToken();

        $idToken = self::customTokenExchanger()->exchangeCustomTokenForIdToken($customToken);

        $facade = new FirebaseJwtFacade(
            variables: self::variables(),
            clock: FrozenClock::at($clock->now()->modify('-11 minutes')),
        );

        $facade->verifyIdToken(jwt: $idToken, leeway: new \DateInterval('PT11M'));
    }
}
