<?php

namespace Beste\Firebase\JWT\Tests\Environment;

use Beste\Firebase\JWT\Environment\EnvironmentVariables;
use Beste\Firebase\JWT\Tests\TestCase;
use PHPUnit\Framework\Attributes\DoesNotPerformAssertions;
use Psl\Env;
use Psl\Json;

/**
 * @internal
 * @covers \Beste\Firebase\JWT\Environment\EnvironmentVariables
 */
final class EnvironmentVariablesTest extends TestCase
{
    private const ENV_VAR = 'ENVIRONMENT_VARIABLES_TEST';

    public function testItFailsWhenGoogleApplicationCredentialsHaveNotBeenSet(): void
    {
        Env\remove_var(self::ENV_VAR);

        self::expectException(\RuntimeException::class);
        EnvironmentVariables::fromEnvironment(self::ENV_VAR);
    }

    #[DoesNotPerformAssertions]
    public function testItReadsAValidFile(): void
    {
        Env\set_var(self::ENV_VAR, __DIR__ . '/credentials.json');

        EnvironmentVariables::fromEnvironment(self::ENV_VAR);
    }

    public function testItRejectsInvalidCredentials(): void
    {
        Env\set_var(self::ENV_VAR, '{}');

        $this->expectException(\RuntimeException::class);

        EnvironmentVariables::fromEnvironment(self::ENV_VAR);
    }

    public function testItAcceptsValidCredentials(): void
    {
        $projectId = 'project';
        $clientEmail = 'service-account@example.org';
        $privateKey = 'private_key';

        Env\set_var(self::ENV_VAR, Json\encode([
            'project_id' => $projectId,
            'client_email' => $clientEmail,
            'private_key' => $privateKey
        ]));

        $variables = EnvironmentVariables::fromEnvironment(self::ENV_VAR);

        self::assertSame($projectId, $variables->projectId());
        self::assertSame($clientEmail, $variables->clientEmail());
        self::assertSame($privateKey, $variables->privateKey());
    }
}
