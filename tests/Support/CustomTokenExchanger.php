<?php

namespace Beste\Firebase\JWT\Tests\Support;

use Lcobucci\JWT\UnencryptedToken;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

/**
 * @internal
 */
final class CustomTokenExchanger
{
    /**
     * @param non-empty-string $projectId
     */
    public function __construct(
        private readonly string $projectId,
        private readonly ClientInterface $client,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly StreamFactoryInterface $streamFactory,
    ) {}

    /**
     * @return non-empty-string
     */
    public function exchangeCustomTokenForIdToken(UnencryptedToken $customToken): string
    {
        $body = [
            'token' => $customToken->toString(),
            'returnSecureToken' => true,
            'targetProjectId' => $this->projectId,
        ];

        $tenantId = $customToken->claims()->get('tenant_id');

        if ($tenantId !== null) {
            $body['tenantId'] = $tenantId;
        }

        $json = json_encode($body);
        assert(is_string($json));

        // dd($customToken->claims()->all(), $json);

        $request = $this->requestFactory
            ->createRequest('POST', 'https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken')
            ->withBody($this->streamFactory->createStream($json))
            ->withHeader('Accept', 'application/json');

        $response = $this->client->sendRequest($request);

        $result = json_decode((string) $response->getBody(), true);
        assert(is_array($result));
        assert(array_key_exists('idToken', $result));

        $idToken =  $result['idToken'];
        assert($idToken !== '');

        return $idToken;
    }
}
