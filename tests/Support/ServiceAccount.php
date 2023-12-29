<?php

namespace Beste\Firebase\JWT\Tests\Support;

/**
 * @internal
 */
final readonly class ServiceAccount
{
    /**
     * @param non-empty-string $privateKey
     * @param non-empty-string $clientEmail
     * @param non-empty-string $projectId
     */
    private function __construct(
        public string $privateKey,
        public string $clientEmail,
        public string $projectId,
    ) {}

    /**
     * @param non-empty-string $path
     */
    public static function fromFile(string $path): self
    {
        $contents = file_get_contents($path);
        assert(is_string($contents) && $contents !== '');

        $json = json_decode($contents, true);
        assert(is_array($json));

        $privateKey = $json['private_key'] ?? '';
        assert(is_string($privateKey) && $privateKey !== '');

        $clientEmail = $json['client_email'] ?? '';
        assert(is_string($clientEmail) && $clientEmail !== '');

        $projectId = $json['project_id'] ?? '';
        assert(is_string($projectId) && $projectId !== '');

        return new self(privateKey: $privateKey, clientEmail: $clientEmail, projectId: $projectId);
    }
}
