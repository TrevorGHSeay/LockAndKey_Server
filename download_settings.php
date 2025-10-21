<?php

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: GET, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type');
    http_response_code(200);
    exit;
}

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *'); // Adjust for security in production
header('Access-Control-Allow-Methods: GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

// Define base CA dir (same as above)
$caDir = getenv('CA_DIR') ?: '/home/Documents/ca'; // Or 'C:/ca' on Windows
$domainsFile = $caDir . '/domains_whitelist.txt';
$formatsFile = $caDir . '/formats_whitelist.txt';
$caRootPemFile = $caDir . '/CARootCert.cer';

// Read permitted domains from file (one per line)
$permittedDomains = [];
if (file_exists($domainsFile)) {
    $domains = file($domainsFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $permittedDomains = array_map('trim', $domains);
} else {
    // Fallback empty
    $permittedDomains = [];
}

// Read permitted domains from file (one per line)
$permittedFormats = [];
if (file_exists($formatsFile)) {
    $formats = file($formatsFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $permittedFormats = array_map('trim', $formats);
} else {
    // Fallback empty
    $permittedFormats = [];
}

// Read permitted domains from file (one per line)
$caRootPem = "";
if (file_exists($formatsFile)) {
    $caRootPem = file($caRootPemFile);
} else {
    // Fallback empty
    $caRootPem = "";
}

echo json_encode([
    'permittedDomains' => $permittedDomains,
    'permittedFormats' => $permittedFormats,
    'caRootPem' => $caRootPem
]);
?>