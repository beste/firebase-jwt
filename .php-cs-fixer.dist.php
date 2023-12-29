<?php

declare(strict_types=1);

$finder = PhpCsFixer\Finder::create()->in(__DIR__);

return (new PhpCsFixer\Config())
    ->setRiskyAllowed(true)
    ->setRules([
        '@PER-CS2.0' => true,
        'final_class' => true,
        'no_unused_imports' => true,
        'ordered_imports' => [
            'imports_order' => [
                'class',
                'function',
                'const',
            ],
            'sort_algorithm' => 'alpha',
        ],
        'php_unit_internal_class' => true,
        'php_unit_test_class_requires_covers' => true,
    ])
    ->setFinder($finder);
