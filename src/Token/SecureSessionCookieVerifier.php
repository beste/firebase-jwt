<?php

namespace Beste\Firebase\JWT\Token;

use Beste\Firebase\JWT\SessionCookieVerifier;
use Beste\Firebase\JWT\Signer\KeySet;
use Beste\Firebase\JWT\Validation\Constraint\AuthTimeValidAt;
use Beste\Firebase\JWT\Validation\Constraint\HasTenant;
use Beste\Firebase\JWT\Validation\Constraint\SignedWithOneInKeySet;
use DateInterval;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Validator;
use Psr\Clock\ClockInterface;

final class SecureSessionCookieVerifier implements SessionCookieVerifier
{
    private DateInterval $leeway;
    private Parser $parser;
    private Validator $validator;

    /**
     * @var non-empty-string|null
     */
    private ?string $tenantId = null;

    /**
     * @param non-empty-string $projectId
     */
    public function __construct(
        private readonly string $projectId,
        private readonly ClockInterface $clock,
        private readonly KeySet $keySet,
    ) {
        $this->leeway = new DateInterval('PT0S');
        $this->parser = new Parser(new JoseEncoder());
        $this->validator = new Validator();
    }

    public function withLeeway(DateInterval $leeway): SessionCookieVerifier
    {
        $new = clone $this;
        $new->leeway = $leeway;

        return $new;
    }

    public function withExpectedTenantId(string $tenantId): SessionCookieVerifier
    {
        $new = clone $this;
        $new->tenantId = $tenantId;

        return $new;
    }

    public function verify(string $jwt): UnencryptedToken
    {
        $token = $this->parser->parse($jwt);
        assert($token instanceof UnencryptedToken);

        $constraints = [
            new LooseValidAt($this->clock, $this->leeway),
            new IssuedBy(...["https://session.firebase.google.com/{$this->projectId}"]),
            new PermittedFor($this->projectId),
            new AuthTimeValidAt($this->clock, $this->leeway),
        ];

        if ($this->tenantId !== null) {
            $constraints[] = new HasTenant($this->tenantId);
        }

        // The key set constraint is asserted last because it uses the internet and/or a cache
        $constraints[] = new SignedWithOneInKeySet($this->keySet, new Sha256());

        $this->validator->assert($token, ...$constraints);

        return $token;
    }
}
