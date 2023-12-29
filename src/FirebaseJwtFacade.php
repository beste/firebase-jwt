<?php

namespace Beste\Firebase\JWT;

use Beste\Cache\InMemoryCache;
use Beste\Firebase\JWT\Environment\EnvironmentVariables;
use Beste\Firebase\JWT\Environment\Variables;
use Beste\Firebase\JWT\Signer\GooglePublicKeys;
use Beste\Firebase\JWT\Signer\KeySet;
use Beste\Firebase\JWT\Token\SecureIdTokenVerifier;
use DateInterval;
use DateTimeImmutable;
use Http\Discovery\Psr17FactoryDiscovery;
use Http\Discovery\Psr18ClientDiscovery;
use Lcobucci\JWT\Encoding\CannotDecodeContent;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\InvalidTokenStructure;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Token\UnsupportedHeaderFound;
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
    private KeySet $keySet;
    private CacheItemPoolInterface|InMemoryCache $cache;

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
        $this->keySet = new GooglePublicKeys($this->client, $this->requestFactory, $this->cache);
    }

    public static function createFromEnvironment(): self
    {
        return new self(EnvironmentVariables::fromEnvironment());
    }

    /**
     * @param non-empty-string $uid
     */
    public function builder(string $uid): Builder
    {
        $builder = new Token\Builder(
            clientEmail: $this->variables->clientEmail(),
            privateKey: $this->variables->privateKey(),
            clock: $this->clock,
        );

        return $builder->relatedToUser($uid);
    }

    /**
     * @param non-empty-string $uid
     * @param array<non-empty-string, mixed> $customClaims
     */
    public function issue(string $uid, array $customClaims = []): UnencryptedToken
    {
        $builder = $this->builder($uid);

        foreach ($customClaims as $name => $value) {
            $builder = $builder->withCustomClaim($name, $value);
        }

        return $builder->getToken();
    }

    /**
     * @param non-empty-string $jwt
     *
     * @throws CannotDecodeContent When something goes wrong while decoding.
     * @throws InvalidTokenStructure When token string structure is invalid.
     * @throws UnsupportedHeaderFound When parsed token has an unsupported header.
     */
    public function parse(string $jwt): UnencryptedToken
    {
        $token = (new Parser(new JoseEncoder()))->parse($jwt);
        assert($token instanceof UnencryptedToken);

        return $token;
    }

    public function verifier(): IdTokenVerifier
    {
        return new SecureIdTokenVerifier($this->variables->projectId(), $this->clock, $this->keySet);
    }

    /**
     * @param non-empty-string $jwt
     * @param non-empty-string|null $expectedTenantId
     */
    public function verify(string $jwt, ?string $expectedTenantId = null, ?DateInterval $leeway = null): UnencryptedToken
    {
        $verifier = $this->verifier();

        if ($expectedTenantId !== null) {
            $verifier = $verifier->withExpectedTenantId($expectedTenantId);
        }

        if ($leeway !== null) {
            $verifier = $verifier->withLeeway($leeway);
        }

        return $verifier->verify($jwt);
    }
}
