<?php

declare(strict_types=1);

namespace Beste\Firebase\JWT\Tests\Environment;

use PHPUnit\Framework\Attributes\CoversClass;
use Beste\Firebase\JWT\Environment\EnvironmentVariables;
use Beste\Firebase\JWT\Tests\TestCase;
use PHPUnit\Framework\Attributes\DoesNotPerformAssertions;

use function Psl\Env\remove_var;
use function Psl\Env\set_var;
use function Psl\Json\encode;

/**
 * @internal
 */
#[CoversClass(EnvironmentVariables::class)]
final class EnvironmentVariablesTest extends TestCase
{
    private const string ENV_VAR = 'ENVIRONMENT_VARIABLES_TEST';

    public function testItFailsWhenGoogleApplicationCredentialsHaveNotBeenSet(): void
    {
        remove_var(self::ENV_VAR);

        self::expectException(\RuntimeException::class);
        EnvironmentVariables::fromEnvironment(self::ENV_VAR);
    }

    #[DoesNotPerformAssertions]
    public function testItReadsAValidFile(): void
    {
        set_var(self::ENV_VAR, __DIR__ . '/credentials.json');

        EnvironmentVariables::fromEnvironment(self::ENV_VAR);
    }

    public function testItRejectsInvalidCredentials(): void
    {
        set_var(self::ENV_VAR, '{}');

        $this->expectException(\RuntimeException::class);

        EnvironmentVariables::fromEnvironment(self::ENV_VAR);
    }

    public function testItAcceptsValidCredentials(): void
    {
        $projectId = 'project';
        $clientEmail = 'service-account@example.org';
        $privateKey = 'private_key';

        set_var(self::ENV_VAR, encode([
            'project_id' => $projectId,
            'client_email' => $clientEmail,
            'private_key' => $privateKey,
        ]));

        $variables = EnvironmentVariables::fromEnvironment(self::ENV_VAR);

        self::assertSame($projectId, $variables->projectId());
        self::assertSame($clientEmail, $variables->clientEmail());
        self::assertSame($privateKey, $variables->privateKey());
    }
}
