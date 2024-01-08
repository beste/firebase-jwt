<?php

namespace Beste\Firebase\JWT\Signer;

final class CertUrl
{
    /**
     * @return non-empty-string
     */
    public static function forIdTokenVerification(): string
    {
        return 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';
    }

    /**
     * @return non-empty-string
     */
    public static function forSessionCookieVerification(): string
    {
        return 'https://www.googleapis.com/identitytoolkit/v3/relyingparty/publicKeys';
    }
}
