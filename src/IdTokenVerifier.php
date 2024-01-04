<?php

namespace Beste\Firebase\JWT;

use DateInterval;
use Lcobucci\JWT\Encoding\CannotDecodeContent;
use Lcobucci\JWT\Token\InvalidTokenStructure;
use Lcobucci\JWT\Token\UnsupportedHeaderFound;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;

/**
 * @see https://firebase.google.com/docs/auth/admin/verify-id-tokens#verify_id_tokens_using_the_firebase_admin_sdk
 */
interface IdTokenVerifier
{
    public function withLeeway(DateInterval $leeway): self;

    /**
     * @param non-empty-string $tenantId
     */
    public function withExpectedTenantId(string $tenantId): self;

    /**
     * @param non-empty-string $jwt
     *
     * @throws RequiredConstraintsViolated
     * @throws CannotDecodeContent When something goes wrong while decoding.
     * @throws InvalidTokenStructure When token string structure is invalid.
     * @throws UnsupportedHeaderFound When parsed token has an unsupported header.
     */
    public function verify(string $jwt): UnencryptedToken;
}
