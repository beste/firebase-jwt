<?php

namespace Beste\Firebase\JWT\Environment;

use Psl;
use Psl\Env;
use Psl\File;
use Psl\Json;
use Psl\Str;
use Psl\Type;
use RuntimeException;
use SensitiveParameter;

final class EnvironmentVariables implements Variables
{
    /**
     * @param non-empty-string $projectId
     * @param non-empty-string $clientEmail
     * @param non-empty-string $privateKey
     */
    public function __construct(
        private readonly string $projectId,
        private readonly string $clientEmail,
        #[SensitiveParameter]
        private readonly string $privateKey,
    ) {}

    /**
     * @param non-empty-string|null $key
     * @throws RuntimeException
     */
    public static function fromEnvironment(?string $key = null): self
    {
        $key ??= 'GOOGLE_APPLICATION_CREDENTIALS';

        $contents = self::getenv($key);

        if (Str\starts_with($contents, '{') === false) {
            $contents = File\read($contents);
        }

        try {
            $serviceAccount = Json\typed($contents, Type\shape([
                'project_id' => Type\non_empty_string(),
                'client_email' => Type\non_empty_string(),
                'private_key' => Type\non_empty_string(),
            ]));
        } catch (Json\Exception\DecodeException $e) {
            throw new RuntimeException('The given Google Application Credentials are invalid: ' . $e->getMessage());
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
        $value = Env\get_var($key);

        Psl\invariant($value !== null && $value !== '', Str\format('Could not find a value for environment variable `%s`', $key));

        return $value;
    }
}
