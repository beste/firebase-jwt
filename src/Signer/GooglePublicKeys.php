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
    private const string KEY_SET_FETCHED_CACHE_KEY = '__key_set_fetched';

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

    public function addKey(string $id, Key $key): void
    {
        $cacheItem = $this->cache->getItem($this->cacheKeyPrefix . $id);
        $cacheItem->set($key->contents());

        if (!$this->cache->save($cacheItem)) {
            throw KeySetError::withReason(format('The key `%s` could not be saved to the cache', $id));
        }
    }

    public function findKeyById(string $id): Key
    {
        $cacheItem = $this->cache->getItem($this->cacheKeyPrefix . $id);
        $value = $cacheItem->get();

        if ($cacheItem->isHit() && (is_string($value) && $value !== '')) {
            return InMemory::plainText($value);
        }

        if ($this->hasFreshKeySet()) {
            throw KeyNotFound::unknownKeyID($id);
        }

        $keys = $this->getKeys();

        if (array_key_exists($id, $keys)) {
            return $keys[$id];
        }

        throw KeyNotFound::unknownKeyID($id);
    }

    /**
     * @return array<non-empty-string, Key>
     */
    private function getKeys(): array
    {
        $response = $this->fetchKeys();

        try {
            $data = typed((string) $response->getBody(), non_empty_dict(non_empty_string(), non_empty_string()));
        } catch (DecodeException $e) {
            throw KeySetError::withReason(format('The response from `%s` could not be parsed: %s', $this->certUrl, $e->getMessage()));
        }

        /** @var array<non-empty-string, Key> $keys */
        $keys = [];
        $expiresAfter = $this->getResponseExpiry($response);

        foreach ($data as $keyId => $value) {
            assert($keyId !== '');

            $key = InMemory::plainText($value);

            $this->addKey($keyId, $key);

            $cacheItem = $this->cache->getItem($this->cacheKeyPrefix . $keyId);
            $cacheItem->expiresAfter($expiresAfter);
            $this->cache->save($cacheItem);

            $keys[$keyId] = $key;
        }

        $cacheItem = $this->cache->getItem($this->cacheKeyPrefix . self::KEY_SET_FETCHED_CACHE_KEY);
        $cacheItem->set(true);
        $cacheItem->expiresAfter($expiresAfter);
        $this->cache->save($cacheItem);

        return $keys;
    }

    private function hasFreshKeySet(): bool
    {
        return $this->cache->getItem($this->cacheKeyPrefix . self::KEY_SET_FETCHED_CACHE_KEY)->isHit();
    }

    private function getResponseExpiry(ResponseInterface $response): ?DateInterval
    {
        $match = first_match(
            $response->getHeaderLine('Cache-Control'),
            '/max-age=(?P<max_age>\d+)/i',
            capture_groups(['max_age']),
        );

        return $match === null ? null : new DateInterval(format('PT%dS', $match['max_age']));
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
