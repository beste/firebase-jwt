<?php

namespace Beste\Firebase\JWT\Tests;

use Beste\Cache\InMemoryCache;
use Beste\Clock\SystemClock;
use Beste\Firebase\JWT\Environment\EnvironmentVariables;
use Beste\Firebase\JWT\Environment\Variables;
use Beste\Firebase\JWT\Tests\Support\CustomTokenExchanger;
use Google\Auth\Credentials\ServiceAccountCredentials;
use Google\Auth\FetchAuthTokenCache;
use Google\Auth\Middleware\AuthTokenMiddleware;
use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;
use Http\Discovery\Psr17FactoryDiscovery;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Builder as LcobucciBuilder;
use PHPUnit\Framework\TestCase as PHPUnitTestCase;
use Psl\Env;

abstract class TestCase extends PHPUnitTestCase
{
    private static ?Variables $variables = null;
    private static ?CustomTokenExchanger $customTokenExchanger = null;

    protected static function variables(): Variables
    {
        if (self::$variables !== null) {
            return self::$variables;
        }

        return self::$variables = EnvironmentVariables::fromEnvironment();
    }

    /**
     * @return non-empty-string
     */
    protected static function tenantId(): string
    {
        $tenantId = Env\get_var('FIREBASE_TENANT_ID');
        assert(is_string($tenantId) && $tenantId !== '');

        return $tenantId;
    }

    protected static function customTokenExchanger(): CustomTokenExchanger
    {
        if (self::$customTokenExchanger instanceof CustomTokenExchanger) {
            return self::$customTokenExchanger;
        }

        $credentials = new ServiceAccountCredentials(['https://www.googleapis.com/auth/cloud-platform'], [
            'client_email' => self::variables()->clientEmail(),
            'private_key' => self::variables()->privateKey(),
        ]);
        $credentials = new FetchAuthTokenCache(fetcher: $credentials, cacheConfig: [], cache: new InMemoryCache(SystemClock::create()));
        $middleware = new AuthTokenMiddleware($credentials);

        $stack = HandlerStack::create();
        $stack->push($middleware);

        $client =  new Client([
            'handler' => $stack,
            'http_errors' => false,
            'auth' => 'google_auth'  // authorize all requests
        ]);
        $requestFactory = Psr17FactoryDiscovery::findRequestFactory();
        $streamFactory = Psr17FactoryDiscovery::findStreamFactory();

        return self::$customTokenExchanger = new CustomTokenExchanger(self::variables()->projectId(), $client, $requestFactory, $streamFactory);
    }

    protected static function lcobucciBuilder(): Builder
    {
        return new LcobucciBuilder(new JoseEncoder(), ChainedFormatter::withUnixTimestampDates());
    }
}
