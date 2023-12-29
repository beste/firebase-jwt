<?php

namespace Beste\Firebase\JWT\Tests;

use Beste\Firebase\JWT\Environment\EnvironmentVariables;
use Beste\Firebase\JWT\Environment\Variables;
use Beste\Firebase\JWT\Tests\Support\CustomTokenExchanger;
use Google\Auth\ApplicationDefaultCredentials;
use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;
use Http\Discovery\Psr17FactoryDiscovery;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Builder as LcobucciBuilder;
use PHPUnit\Framework\TestCase as PHPUnitTestCase;

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
        $tenantId = $_ENV['FIREBASE_TENANT_ID'];
        assert(is_string($tenantId) && $tenantId !== '');

        return $tenantId;
    }

    protected static function customTokenExchanger(): CustomTokenExchanger
    {
        if (self::$customTokenExchanger instanceof CustomTokenExchanger) {
            return self::$customTokenExchanger;
        }

        $middleware = ApplicationDefaultCredentials::getMiddleware(['https://www.googleapis.com/auth/cloud-platform']);

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
