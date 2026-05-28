<?php

declare(strict_types=1);

namespace Beste\Firebase\JWT\Signer;

use Psl\Json\Exception\DecodeException;
use DateInterval;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\InMemory;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\ResponseInterface;

use function Psl\Json\typed;
use function Psl\Type\non_empty_dict;
use function Psl\Type\non_empty_string;
use function Psl\Str\format;
use function Psl\Regex\first_match;
use function Psl\Regex\capture_groups;

final readonly class GooglePublicKeys implements KeySet
{
    /**
     * @param non-empty-string $certUrl
     */
    public function __construct(
        private string $certUrl,
        private ClientInterface $client,
        private RequestFactoryInterface $requestFactory,
        private CacheItemPoolInterface $cache,
        private string $cacheKeyPrefix = 'bfj_',
    ) {}


    public function findKeyById(string $id): Key
    {
        $cacheItem = $this->cache->getItem($this->cacheKeyPrefix . $id);
        $value = $cacheItem->get();

        if ($cacheItem->isHit() && (is_string($value) && $value !== '')) {
            return InMemory::plainText($value);
        }

        $response = $this->fetchKeys();

        try {
            $data = typed((string) $response->getBody(), non_empty_dict(non_empty_string(), non_empty_string()));
        } catch (DecodeException $e) {
            throw KeySetError::withReason(format('The response from `%s` could not be parsed: %s', $this->certUrl, $e->getMessage()));
        }

        $key = null;

        foreach ($data as $keyId => $candidate) {
            if ($keyId === $id) {
                $key = InMemory::plainText($candidate);
            }
        }

        $cacheItem->set($key?->contents());
        $cacheItem->expiresAfter($this->getResponseExpiry($response));
        $this->cache->save($cacheItem);

        if ($key instanceof InMemory) {
            return $key;
        }

        throw KeyNotFound::unknownKeyID($id);
    }

    private function getResponseExpiry(ResponseInterface $response): ?DateInterval
    {
        $match = first_match(
            $response->getHeaderLine('Cache-Control'),
            '/max-age=(?P<max_age>\d+)/i',
            capture_groups(['max_age']),
        );

        return $match === null ? null : new DateInterval(format('PT%dM', $match['max_age']));
    }

    private function fetchKeys(): ResponseInterface
    {
        $request = $this->requestFactory->createRequest('GET', $this->certUrl);

        try {
            $response = $this->client->sendRequest($request);
        } catch (ClientExceptionInterface $e) {
            throw KeySetError::withReason('Network error while fetching Google Public Keys from ' . $this->certUrl . ': ' . $e->getMessage());
        }

        if ($response->getStatusCode() !== 200) {
            throw KeySetError::withReason(format('The call to %s returned an unsuccessful response: (%d) %s', $this->certUrl, $response->getStatusCode(), (string) $response->getBody()));
        }

        return $response;
    }
}
