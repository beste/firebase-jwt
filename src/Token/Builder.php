<?php

namespace Beste\Firebase\JWT\Token;

use Beste\Firebase\JWT\Builder as BuilderInterface;
use DateInterval;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Builder as LcobucciBuilder;
use Lcobucci\JWT\UnencryptedToken;
use Psr\Clock\ClockInterface;
use SensitiveParameter;

final class Builder implements BuilderInterface
{
    private const AUDIENCE = 'https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit';
    private const DEFAULT_TTL = 'PT5M';

    private InMemory $privateKey;
    private Signer $signer;
    private DateInterval $expiresAfter;

    /**
     * @var array<non-empty-string, mixed>
     */
    private array $claims = [];

    /**
     * @var array<non-empty-string, mixed>
     */
    private array $customClaims = [];

    /**
     * @param non-empty-string $clientEmail
     * @param non-empty-string $privateKey
     */
    public function __construct(
        private readonly string $clientEmail,
        #[SensitiveParameter]
        string $privateKey,
        private readonly ClockInterface $clock,
    ) {
        $this->privateKey = InMemory::plainText($privateKey);
        $this->signer = new Sha256();

        $this->expiresAfter = new DateInterval(self::DEFAULT_TTL);
    }

    public function relatedToUser(string $uid): BuilderInterface
    {
        return $this->withClaim('uid', $uid);
    }

    public function relatedToTenant(string $tenantId): BuilderInterface
    {
        return $this->withClaim('tenant_id', $tenantId);
    }

    public function withClaim(string $name, mixed $value): BuilderInterface
    {
        $new = clone $this;
        $new->claims[$name] = $value;

        return $new;
    }

    public function withCustomClaim(string $name, mixed $value): BuilderInterface
    {
        $new = clone $this;
        $new->customClaims[$name] = $value;

        return $new;
    }

    public function expiresAfter(DateInterval $duration): BuilderInterface
    {
        $new = clone $this;
        $new->expiresAfter = $duration;

        return $new;
    }

    public function getToken(): UnencryptedToken
    {
        $now = $this->clock->now();

        $builder = (new LcobucciBuilder(new JoseEncoder(), ChainedFormatter::withUnixTimestampDates()))
            ->issuedBy($this->clientEmail)
            ->relatedTo($this->clientEmail)
            ->issuedAt($now)
            ->expiresAt($now->add($this->expiresAfter))
            ->canOnlyBeUsedAfter($now)
            ->permittedFor(self::AUDIENCE)
        ;

        foreach ($this->claims as $name => $value) {
            $builder = $builder->withClaim($name, $value);
        }

        if ($this->customClaims !== []) {
            $builder = $builder->withClaim('claims', $this->customClaims);
        }

        return $builder->getToken($this->signer, $this->privateKey);
    }
}
