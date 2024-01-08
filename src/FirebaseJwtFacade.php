<?php

namespace Beste\Firebase\JWT;

use Beste\Cache\InMemoryCache;
use Beste\Firebase\JWT\Environment\EnvironmentVariables;
use Beste\Firebase\JWT\Environment\Variables;
use Beste\Firebase\JWT\Signer\CertUrl;
use Beste\Firebase\JWT\Signer\GooglePublicKeys;
use Beste\Firebase\JWT\Token\SecureIdTokenVerifier;
use Beste\Firebase\JWT\Token\SecureSessionTokenVerifier;
use DateInterval;
use DateTimeImmutable;
use Http\Discovery\Psr17FactoryDiscovery;
use Http\Discovery\Psr18ClientDiscovery;
use Lcobucci\JWT\UnencryptedToken;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Clock\ClockInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;

final class FirebaseJwtFacade
{
    private ClockInterface $clock;
    private ClientInterface $client;
    private RequestFactoryInterface $requestFactory;
    private CacheItemPoolInterface $cache;

    public function __construct(
        private readonly Variables $variables,
        ?ClockInterface $clock = null,
        ?ClientInterface $client = null,
        ?RequestFactoryInterface $requestFactory = null,
        ?CacheItemPoolInterface $cache = null,
    ) {
        $this->clock = $clock ?? new class () implements ClockInterface {
            public function now(): DateTimeImmutable
            {
                return new DateTimeImmutable();
            }
        };
        $this->client = $client ?? Psr18ClientDiscovery::find();
        $this->requestFactory = $requestFactory ?? Psr17FactoryDiscovery::findRequestFactory();
        $this->cache = $cache ?? new InMemoryCache($this->clock);
    }

    /**
     * @param non-empty-string|null $name
     */
    public static function createFromEnvironment(?string $name = null): self
    {
        return new self(EnvironmentVariables::fromEnvironment($name));
    }

    /**
     * @param non-empty-string $uid
     */
    private function customTokenBuilder(string $uid): CustomTokenBuilder
    {
        $builder = new Token\CustomTokenBuilder(
            clientEmail: $this->variables->clientEmail(),
            privateKey: $this->variables->privateKey(),
            clock: $this->clock,
        );

        return $builder->forUser($uid);
    }

    /**
     * @param non-empty-string $uid
     * @param array<non-empty-string, mixed> $customClaims
     * @param non-empty-string|null $tenantId
     */
    public function issueCustomToken(string $uid, ?array $customClaims = null, ?string $tenantId = null): UnencryptedToken
    {
        $customClaims ??= [];

        $builder = $this->customTokenBuilder($uid);

        foreach ($customClaims as $name => $value) {
            $builder = $builder->withCustomClaim($name, $value);
        }

        if ($tenantId !== null) {
            $builder = $builder->forTenant($tenantId);
        }

        return $builder->getToken();
    }

    private function idTokenVerifier(): IdTokenVerifier
    {
        return new SecureIdTokenVerifier(
            projectId: $this->variables->projectId(),
            clock: $this->clock,
            keySet: new GooglePublicKeys(
                CertUrl::forIdTokenVerification(),
                $this->client,
                $this->requestFactory,
                $this->cache,
            )
        );
    }

    /**
     * @param non-empty-string $jwt
     * @param non-empty-string|null $expectedTenantId
     */
    public function verifyIdToken(string $jwt, ?string $expectedTenantId = null, ?DateInterval $leeway = null): UnencryptedToken
    {
        $verifier = $this->idTokenVerifier();

        if ($expectedTenantId !== null) {
            $verifier = $verifier->withExpectedTenantId($expectedTenantId);
        }

        if ($leeway !== null) {
            $verifier = $verifier->withLeeway($leeway);
        }

        return $verifier->verify($jwt);
    }

    private function sessionCookieVerifier(): SessionTokenVerifier
    {
        return new SecureSessionTokenVerifier(
            projectId: $this->variables->projectId(),
            clock: $this->clock,
            keySet: new GooglePublicKeys(
                CertUrl::forSessionCookieVerification(),
                $this->client,
                $this->requestFactory,
                $this->cache,
            )
        );
    }

    /**
     * @param non-empty-string $jwt
     * @param non-empty-string|null $expectedTenantId
     */
    public function verifySessionCookie(string $jwt, ?string $expectedTenantId = null, ?DateInterval $leeway = null): UnencryptedToken
    {
        $verifier = $this->sessionCookieVerifier();

        if ($expectedTenantId !== null) {
            $verifier = $verifier->withExpectedTenantId($expectedTenantId);
        }

        if ($leeway !== null) {
            $verifier = $verifier->withLeeway($leeway);
        }

        return $verifier->verify($jwt);
    }
}
