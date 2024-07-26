<?php

namespace Beste\Firebase\JWT\Signer;

use DateInterval;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\InMemory;
use Psl\Json;
use Psl\Regex;
use Psl\Str;
use Psl\Type;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\ResponseInterface;

final class GooglePublicKeys implements KeySet
{
    /**
     * @param non-empty-string $certUrl
     */
    public function __construct(
        private readonly string $certUrl,
        private readonly ClientInterface $client,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly CacheItemPoolInterface $cache,
        private readonly string $cacheKeyPrefix = 'bfj_',
    ) {}


    public function findKeyById(string $id): Key
    {
        $cacheItem = $this->cache->getItem($this->cacheKeyPrefix . $id);
        $value = $cacheItem->get();

        if ($cacheItem->isHit()) {
            if (is_string($value) && $value !== '') {
                return InMemory::plainText($value);
            }
        }

        $response = $this->fetchKeys();

        try {
            $data = Json\typed((string) $response->getBody(), Type\non_empty_dict(Type\non_empty_string(), Type\non_empty_string()));
        } catch (Json\Exception\DecodeException $e) {
            throw KeySetError::withReason(Str\format('The response from `%s` could not be parsed: %s', $this->certUrl, $e->getMessage()));
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

        if ($key !== null) {
            return $key;
        }

        throw KeyNotFound::unknownKeyID($id);
    }

    private function getResponseExpiry(ResponseInterface $response): ?DateInterval
    {
        $match = Regex\first_match(
            $response->getHeaderLine('Cache-Control'),
            '/max-age=(?P<max_age>\d+)/i',
            Regex\capture_groups(['max_age']),
        );

        return $match === null ? null : new DateInterval(Str\format('PT%dM', $match['max_age']));
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
            throw KeySetError::withReason(Str\format('The call to %s returned an unsuccessful response: (%d) %s', $this->certUrl, $response->getStatusCode(), (string) $response->getBody()));
        }

        return $response;
    }
}
