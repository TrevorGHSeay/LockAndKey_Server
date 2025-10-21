<?php

$openSslPassword = "CyB@ter123"; 

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');  // Adjust for your domain in prod
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

// Handle CORS preflight (OPTIONS request)
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
  http_response_code(200);
  exit;
}

// Only process POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
  http_response_code(405);
  echo json_encode(['success' => false, 'error' => 'Method not allowed']);
  exit;
}

// Parse CSR from POST body (assume JSON { "csr": "PEM string" })
$input = json_decode(file_get_contents('php://input'), true);
if (!isset($input['csr']) || empty(trim($input['csr']))) {
  echo json_encode(['success' => false, 'error' => 'Missing or invalid CSR']);
  exit;
}

$csrPem = trim($input['csr']);

// Temp files for secure processing (OS-agnostic)
$tempCsr = sys_get_temp_dir() . DIRECTORY_SEPARATOR . uniqid('csr_') . '.pem';
$tempCert = sys_get_temp_dir() . DIRECTORY_SEPARATOR . uniqid('cert_') . '.pem';

// Save CSR to temp file
if (file_put_contents($tempCsr, $csrPem) === false) {
  echo json_encode(['success' => false, 'error' => 'Failed to save CSR']);
  exit;
}


// Find OpenSSL binary (OS-agnostic)
$opensslBin = null;
$isWindows = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';

// CA Config (relative paths for portability; adjust to your CA setup)

$ca = $isWindows ? "C:/ca" : "/home/Documents/ca";

$caConfig = $ca . DIRECTORY_SEPARATOR . 'openssl.cnf';  // CA config
$caNewCertsDir = $ca . DIRECTORY_SEPARATOR . 'newcerts' . DIRECTORY_SEPARATOR;  // Output dir

// Ensure newcerts dir exists
if (!is_dir($caNewCertsDir)) {
  mkdir($caNewCertsDir, 0755, true);
}

// Step 1: Try 'which' (Linux/macOS) or 'where' (Windows)
$whichCmd = $isWindows ? 'where openssl' : 'which openssl';
exec($whichCmd, $whichOutput, $whichReturnCode);
if ($whichReturnCode === 0 && !empty($whichOutput)) {
  $opensslBin = trim($whichOutput[0]);
}

// Step 2: Final check
if (!$opensslBin || !file_exists($opensslBin)) {
  @unlink($tempCsr);
  echo json_encode(['success' => false, 'error' => 'OpenSSL binary not found']);
  exit;
}

// Verify OpenSSL is executable
$testCmd = escapeshellcmd($opensslBin) . ' version 2>&1';
exec($testCmd, $testOutput, $testReturnCode);
if ($testReturnCode !== 0) {
  @unlink($tempCsr);
  echo json_encode(['success' => false, 'error' => 'OpenSSL not executable: ' . implode("\n", $testOutput)]);
  exit;
}

// Run OpenSSL CA command to sign CSR
$cmd = escapeshellcmd($opensslBin) . 
       " ca -config " . escapeshellarg($caConfig) . 
       " -in " . escapeshellarg($tempCsr) . 
       " -out " . escapeshellarg($tempCert) . 
       " -passin pass:$openSslPassword" .
       " -batch 2>&1";

$caOutput = [];
$returnCode = 0;
exec($cmd, $caOutput, $returnCode);

// Check for success
if ($returnCode !== 0 || !file_exists($tempCert) || filesize($tempCert) === 0) {
  $error = implode("\n", $caOutput) ?: 'CA signing failed';
  @unlink($tempCsr);
  @unlink($tempCert);
  echo json_encode(['success' => false, 'error' => $error]);
  exit;
}

// Read signed certificate
$certificatePem = file_get_contents($tempCert);
if ($certificatePem === false) {
  @unlink($tempCsr);
  @unlink($tempCert);
  echo json_encode(['success' => false, 'error' => 'Failed to read certificate']);
  exit;
}

// Clean up temp files
@unlink($tempCsr);
@unlink($tempCert);

// Return success with cert
echo json_encode([
  'success' => true,
  'certificate' => trim($certificatePem)
]);
?>