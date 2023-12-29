<?php

namespace Beste\Firebase\JWT;

use DateInterval;
use Lcobucci\JWT\UnencryptedToken;

/**
 * @see https://firebase.google.com/docs/auth/admin/create-custom-tokens#create_custom_tokens_using_a_third-party_jwt_library
 */
interface Builder
{
    /**
     * @param non-empty-string $uid
     */
    public function relatedToUser(string $uid): self;

    /**
     * @param non-empty-string $tenantId
     */
    public function relatedToTenant(string $tenantId): self;

    /**
     * @param non-empty-string $name
     */
    public function withClaim(string $name, mixed $value): self;

    /**
     * Optional custom claims to include in the Security Rules auth / request.auth variables
     *
     * @param non-empty-string $name
     */
    public function withCustomClaim(string $name, mixed $value): self;

    public function expiresAfter(DateInterval $duration): self;

    public function getToken(): UnencryptedToken;
}
