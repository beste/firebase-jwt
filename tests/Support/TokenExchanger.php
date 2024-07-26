<?php

namespace Beste\Firebase\JWT\Tests\Support;

use Beste\Clock\SystemClock;
use DateInterval;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Psr\Clock\ClockInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

/**
 * @internal
 */
final class TokenExchanger
{
    private Parser $parser;
    private ClockInterface $clock;

    /**
     * @param non-empty-string $projectId
     */
    public function __construct(
        private readonly string $projectId,
        private readonly ClientInterface $client,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly StreamFactoryInterface $streamFactory,
    ) {
        $this->parser = new Parser(new JoseEncoder());
        $this->clock = SystemClock::create();
    }

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

        $request = $this->requestFactory
            ->createRequest('POST', 'https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken')
            ->withBody($this->streamFactory->createStream($json))
            ->withHeader('Accept', 'application/json')
        ;

        $response = $this->client->sendRequest($request);
        assert($response->getStatusCode() === 200);

        $result = json_decode((string) $response->getBody(), true);
        assert(is_array($result));
        assert(array_key_exists('idToken', $result));

        $idToken =  $result['idToken'];
        assert($idToken !== '');

        return $idToken;
    }

    /**
     * @return non-empty-string
     */
    public function exchangeIdTokenForSessionCookie(Token $idToken, ?string $tenantId = null, ?DateInterval $expiresAfter = null): string
    {
        $expiresAfter ??= new DateInterval('PT5M');

        $now = $this->clock->now();
        $then = $now->add($expiresAfter);
        $durationInSeconds = $then->getTimestamp() - $now->getTimestamp();

        $body = [
            'idToken' => $idToken->toString(),
            'validDuration' => $durationInSeconds,
        ];

        $json = json_encode($body);
        assert(is_string($json));

        $url = "https://identitytoolkit.googleapis.com/v1/projects/{$this->projectId}:createSessionCookie";

        if ($tenantId !== null) {
            $url = "https://identitytoolkit.googleapis.com/v1/projects/{$this->projectId}/tenants/{$tenantId}:createSessionCookie";
        }

        $request = $this->requestFactory
            ->createRequest('POST', $url)
            ->withBody($this->streamFactory->createStream($json))
            ->withHeader('Accept', 'application/json')
        ;

        $response = $this->client->sendRequest($request);
        assert($response->getStatusCode() === 200);

        $result = json_decode((string) $response->getBody(), true);
        assert(is_array($result));
        assert(array_key_exists('sessionCookie', $result));

        $sessionCookie =  $result['sessionCookie'];
        assert($sessionCookie !== '');

        return $sessionCookie;
    }

    /**
     * @return non-empty-string
     */
    public function exchangeCustomTokenForSessionCookie(UnencryptedToken $customToken, ?string $tenantId = null, ?DateInterval $idTokenExpiresAfter = null): string
    {
        $idToken = $this->exchangeCustomTokenForIdToken($customToken);
        $t = $this->parser->parse($idToken);

        return  $this->exchangeIdTokenForSessionCookie(
            idToken: $this->parser->parse($idToken),
            tenantId: $tenantId,
            expiresAfter: $idTokenExpiresAfter,
        );
    }
}
