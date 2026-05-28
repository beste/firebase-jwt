<?php

declare(strict_types=1);

namespace Beste\Firebase\JWT\Environment;

use Psl\Json\Exception\DecodeException;
use RuntimeException;
use SensitiveParameter;

use function Psl\Str\starts_with;
use function Psl\File\read;
use function Psl\Json\typed;
use function Psl\Type\shape;
use function Psl\Type\non_empty_string;
use function Psl\Env\get_var;
use function Psl\invariant;
use function Psl\Str\format;

final readonly class EnvironmentVariables implements Variables
{
    /**
     * @param non-empty-string $projectId
     * @param non-empty-string $clientEmail
     * @param non-empty-string $privateKey
     */
    public function __construct(
        private string $projectId,
        private string $clientEmail,
        #[SensitiveParameter]
        private string $privateKey,
    ) {}

    /**
     * @param non-empty-string|null $key
     * @throws RuntimeException
     */
    public static function fromEnvironment(?string $key = null): self
    {
        $key ??= 'GOOGLE_APPLICATION_CREDENTIALS';

        $contents = self::getenv($key);

        if (starts_with($contents, '{') === false) {
            $contents = read($contents);
        }

        try {
            $serviceAccount = typed($contents, shape([
                'project_id' => non_empty_string(),
                'client_email' => non_empty_string(),
                'private_key' => non_empty_string(),
            ]));
        } catch (DecodeException $e) {
            throw new RuntimeException('The given Google Application Credentials are invalid: ' . $e->getMessage(), $e->getCode(), $e);
        }


        return new self(
            projectId: $serviceAccount['project_id'],
            clientEmail: $serviceAccount['client_email'],
            privateKey: $serviceAccount['private_key'],
        );
    }

    public function projectId(): string
    {
        return $this->projectId;
    }

    public function clientEmail(): string
    {
        return $this->clientEmail;
    }

    public function privateKey(): string
    {
        return $this->privateKey;
    }

    /**
     * @param non-empty-string $key
     *
     * @return non-empty-string
     */
    private static function getenv(string $key): string
    {
        $value = get_var($key);

        invariant($value !== null && $value !== '', format('Could not find a value for environment variable `%s`', $key));

        return $value;
    }
}
