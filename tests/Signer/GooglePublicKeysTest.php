<?php

namespace Beste\Firebase\JWT\Tests\Signer;

use Beste\Cache\InMemoryCache;
use Beste\Clock\FrozenClock;
use Beste\Firebase\JWT\Signer\GooglePublicKeys;
use Beste\Firebase\JWT\Signer\KeyNotFound;
use Beste\Firebase\JWT\Signer\KeySetError;
use Beste\Firebase\JWT\Tests\TestCase;
use Http\Discovery\Psr17FactoryDiscovery;
use PHPUnit\Framework\Attributes\DoesNotPerformAssertions;
use PHPUnit\Framework\MockObject\MockObject;
use Psl\Json;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

/**
 * @covers \Beste\Firebase\JWT\Signer\GooglePublicKeys
 * @covers \Beste\Firebase\JWT\Signer\KeyNotFound
 * @covers \Beste\Firebase\JWT\Signer\KeySetError
 * @internal
 */
final class GooglePublicKeysTest extends TestCase
{
    private MockObject&ClientInterface $mockedClient;
    private RequestFactoryInterface $requestFactory;
    private ResponseFactoryInterface $responseFactory;
    private StreamFactoryInterface $streamFactory;
    private FrozenClock $clock;
    private InMemoryCache $cache;

    protected function setUp(): void
    {
        $this->mockedClient = $this->createMock(ClientInterface::class);
        $this->requestFactory = Psr17FactoryDiscovery::findRequestFactory();
        $this->responseFactory = Psr17FactoryDiscovery::findResponseFactory();
        $this->streamFactory = Psr17FactoryDiscovery::findStreamFactory();
        $this->clock = FrozenClock::fromUTC();
        $this->cache = new InMemoryCache($this->clock);
    }

    public function testItHandlesClientExceptions(): void
    {
        $keySet = $this->keySetWithMockedClient();

        $exception = new class () extends \RuntimeException implements ClientExceptionInterface {};

        $this->mockedClient
            ->method('sendRequest')
            ->withAnyParameters()
            ->willThrowException(new $exception(__FUNCTION__));

        $this->expectException(KeySetError::class);

        $keySet->findKeyById('foo');
    }

    public function testItHandlesJsonErrors(): void
    {
        $keySet = $this->keySetWithMockedClient();
        $response = $this->responseFactory->createResponse(code: 200)
            ->withBody($this->streamFactory->createStream('{'));

        $this->mockedClient
            ->method('sendRequest')
            ->withAnyParameters()
            ->willReturn($response);

        $this->expectException(KeySetError::class);

        $keySet->findKeyById('foo');
    }

    public function testItHandlesJsonWithoutAnArrayOfKeys(): void
    {
        $keySet = $this->keySetWithMockedClient();
        $response = $this->responseFactory->createResponse(code: 200)
            ->withBody($this->streamFactory->createStream('"not an object"'));

        $this->mockedClient
            ->method('sendRequest')
            ->withAnyParameters()
            ->willReturn($response);

        $this->expectException(KeySetError::class);

        $keySet->findKeyById('foo');
    }

    #[DoesNotPerformAssertions]
    public function testItFindsAKey(): void
    {
        $keySet = $this->keySetWithMockedClient();
        $response = $this->responseFactory->createResponse(code: 200)
            ->withBody($this->streamFactory->createStream(Json\encode(['foo' => '-----BEGIN CERTIFICATE-----'])));

        $this->mockedClient
            ->method('sendRequest')
            ->withAnyParameters()
            ->willReturn($response);

        $keySet->findKeyById('foo');
    }

    public function testItDoesNotFindAKey(): void
    {
        $keySet = $this->keySetWithMockedClient();
        $response = $this->responseFactory->createResponse(code: 200)
            ->withBody($this->streamFactory->createStream(Json\encode(['kid' => 'key'])));

        $this->mockedClient
            ->method('sendRequest')
            ->withAnyParameters()
            ->willReturn($response);

        $this->expectException(KeyNotFound::class);
        $keySet->findKeyById('bar');
    }

    public function testItHandlesUnsuccessfulResponses(): void
    {
        $keySet = $this->keySetWithMockedClient();

        $response = $this->responseFactory->createResponse(code: 500)
            ->withBody($this->streamFactory->createStream('Error'));

        $this->mockedClient
            ->method('sendRequest')
            ->withAnyParameters()
            ->willReturn($response);

        $this->expectException(KeySetError::class);
        $keySet->findKeyById('foo');
    }

    public function testItReturnsACachedKey(): void
    {
        $keySet = $this->keySetWithMockedClient();

        $response = $this->responseFactory->createResponse(code: 200)
            ->withBody($this->streamFactory->createStream(Json\encode(['kid' => 'key'])))
            ->withHeader('Cache-Control', 'max-age=60');

        $this->mockedClient
            ->expects(self::once())
            ->method('sendRequest')
            ->withAnyParameters()
            ->willReturn($response);

        $keySet->findKeyById('kid');
        $keySet->findKeyById('kid');
    }

    public function testItCachesKeysAsLongAsTheResponseSaysTo(): void
    {
        $keySet = $this->keySetWithMockedClient(cacheKeyPrefix: 'prefix_');

        $response = $this->responseFactory->createResponse(code: 200)
            ->withBody($this->streamFactory->createStream(Json\encode(['kid' => 'key'])))
            ->withHeader('Cache-Control', 'max-age=60');

        $this->mockedClient
            ->method('sendRequest')
            ->withAnyParameters()
            ->willReturn($response);

        $keySet->findKeyById('kid');

        assert($this->cache->getItem('prefix_kid')->isHit() === true); // We don't test this, just assert the pre-condition is true

        $this->clock->setTo($this->clock->now()->modify('+61 minutes'));

        self::assertFalse($this->cache->getItem('prefix_kid')->isHit());
    }

    private function keySetWithMockedClient(string $cacheKeyPrefix = 'test'): GooglePublicKeys
    {
        return new GooglePublicKeys(
            client: $this->mockedClient,
            requestFactory: $this->requestFactory,
            cache: $this->cache,
            cacheKeyPrefix: $cacheKeyPrefix,
        );
    }

    /**
     * @return iterable<array<array<string, string>>>
     */
    public static function invalidKeys(): iterable
    {
        yield "empty key" => [
            ["" => '-----BEGIN CERTIFICATE-----']
        ];

        yield "unexpected value" => [
            ["key_id" => 'not a certificate']
        ];
    }
}
