<?php

require_once __DIR__ . '/../vendor/autoload.php';

// Unsafe is needed because google/auth uses getenv/putenv to determine the Application Credentials
$dotenv = Dotenv\Dotenv::createUnsafeImmutable(__DIR__);
$dotenv->safeLoad();
$dotenv->required('GOOGLE_APPLICATION_CREDENTIALS');
$dotenv->required('FIREBASE_TENANT_ID');
