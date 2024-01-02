<?php

namespace Beste\Firebase\JWT\Tests;

use Beste\Clock\FrozenClock;
use Beste\Clock\SystemClock;
use Beste\Firebase\JWT\FirebaseJwtFacade;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Builder as LcobucciBuilder;
use Lcobucci\JWT\Token\Parser;
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
        $token = $this->facade->issueCustomToken('uid', ['custom' => 'claim']);

        $parsed = (new Parser(new JoseEncoder()))->parse($token->toString());

        self::assertSame($token->toString(), $parsed->toString());
    }

    public function testItParsesAJwt(): void
    {
        $token = (new LcobucciBuilder(new JoseEncoder(), ChainedFormatter::withUnixTimestampDates()))
            ->getToken($this->signer, InMemory::plainText(self::variables()->privateKey()));

        $parsed = $this->facade->parse($token->toString());

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

        $customToken = $this->facade->customTokenBuilder('uid')->relatedToTenant($tenantId)->getToken();
        $idToken = self::customTokenExchanger()->exchangeCustomTokenForIdToken($customToken);

        $this->facade->verifyIdToken($idToken, $tenantId);
    }

    #[DoesNotPerformAssertions]
    public function testItVerifiesAnExpiredItTokenWithLeeway(): void
    {
        $correctClock = SystemClock::create();
        $futureClock = FrozenClock::fromUTC();
        $futureClock->setTo($futureClock->now()->modify('+1 hour'));

        $correctFacade = new FirebaseJwtFacade(
            variables: self::variables(),
            clock: $correctClock
        );
        $futureFacade = new FirebaseJwtFacade(
            variables: self::variables(),
            clock: $futureClock
        );

        $customToken = $correctFacade->customTokenBuilder('uid')
            ->expiresAfter(new \DateInterval('PT10M'))
            ->getToken();

        $idToken = self::customTokenExchanger()->exchangeCustomTokenForIdToken($customToken);

        $futureFacade->verifyIdToken(jwt: $idToken, leeway: new \DateInterval('PT51M'));
    }
}
