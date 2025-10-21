<?php
// validate_signature.php - Simplified for CRL revocation check only
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: chrome-extension://njnjekhpbjohlgjghfggmmjikhplilhg'); // Use your extension's ID
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
    echo json_encode(['valid' => false, 'reasons' => ['Method not allowed']]);
    exit;
}

// Ensure uploads directory exists and is writable
$target_dir = "uploads/";
if (!is_dir($target_dir)) {
    if (!mkdir($target_dir, 0755, true)) {
        echo json_encode(['valid' => false, 'reasons' => ['Failed to create uploads directory']]);
        exit;
    }
}
if (!is_writable($target_dir)) {
    echo json_encode(['valid' => false, 'reasons' => ['Uploads directory not writable']]);
    exit;
}

$target_fileX509 = $target_dir . uniqid() . '_cert.pem';

// Get cert PEM: prefer file upload, fallback to raw POST string
$certPem = '';
if (isset($_FILES["fileToUploadX509"]) && !empty($_FILES["fileToUploadX509"]["tmp_name"])) {
    
    // Error uploading
    if ($_FILES["fileToUploadX509"]["error"] !== UPLOAD_ERR_OK) {
        echo json_encode(['valid' => false, 'reasons' => ['Upload error: ' . $_FILES["fileToUploadX509"]["error"]]]);
        exit;
    }

    // Cert way too big to be valid
    if ($_FILES["fileToUploadX509"]["size"] > 8192) {  // Increased limit for larger PEM certs (~4KB max)
        echo json_encode(['valid' => false, 'reasons' => ['Certificate file too large']]);
        exit;
    }

    // Can't move the file to a decent location
    if (!move_uploaded_file($_FILES["fileToUploadX509"]["tmp_name"], $target_fileX509)) {
        // Debug: Log why it failed
        //error_log("move_uploaded_file failed: tmp_name=" . $_FILES["fileToUploadX509"]["tmp_name"] . ", target=" . $target_fileX509 . ", error=" . error_get_last()['message']);
        echo json_encode(['valid' => false, 'reasons' => ['Upload error: Failed to move file']]);
        @unlink($target_fileX509);
        exit;
    }

    $certPem = file_get_contents($target_fileX509);

}

elseif (isset($_POST["fileToUploadX509"]) && !empty(trim($_POST["fileToUploadX509"]))) {
    // Raw text case
    $certPem = trim($_POST["fileToUploadX509"]);

    // Cert way too big to be valid
    if (strlen($certPem) > 8192) {  // Increased limit
        echo json_encode(['valid' => false, 'reasons' => ['Certificate text too large']]);
        exit;
    }

    // Can't write cert to file
    if (!file_put_contents($target_fileX509, $certPem)) {
        echo json_encode(['valid' => false, 'reasons' => ['Failed to write temp cert']]);
        @unlink($target_fileX509);
        exit;
    }
}
else {
    // No cert found
    echo json_encode(['valid' => false, 'reasons' => ['Missing certificate']]);
    exit;
}

// Validate PEM format (basic check)
if (!preg_match('/-----BEGIN CERTIFICATE-----/', $certPem) || !preg_match('/-----END CERTIFICATE-----/', $certPem)) {
    @unlink($target_fileX509);
    echo json_encode(['valid' => false, 'reasons' => ['Invalid PEM format']]);
    exit;
}


// Detect OS and set paths from setup_ca.sh
$isWindows = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
$baseDir = $isWindows ? 'C:/ca' : '/home/Documents/ca';
$caRoot = "$baseDir/CARootCert.cer"; // Root cert (.cer, but PEM format)
$crlPath = "$baseDir/crl/crl.pem"; // CRL file

// Verify paths exist
if (!file_exists($caRoot)) {
    @unlink($target_fileX509);
    echo json_encode(['valid' => false, 'reasons' => ["CA root cert not found: $caRoot"]]);
    exit;
}
if (!file_exists($crlPath)) {
    @unlink($target_fileX509);
    echo json_encode(['valid' => false, 'reasons' => ["CRL not found: $crlPath"]]);
    exit;
}


// Find OpenSSL binary (Windows-focused, as per setup)
$opensslBin = 'openssl';  // Default: Assume in PATH
if ($isWindows) {
    $possiblePaths = [
        'C:\\Program Files\\OpenSSL-Win64\\bin\\openssl.exe',
        'C:\\OpenSSL-Win64\\bin\\openssl.exe',
        'C:\\Users\\Trevor\\Documents\\OpenSSL-Win64\\bin\\openssl.exe'
    ];
    foreach ($possiblePaths as $path) {
        if (file_exists($path)) {
            $opensslBin = $path;
            break;
        }
    }
}


$valid = true;
$reasons = [];

// TODO: Verify against revocation list
/*
// CRL Revocation Check
$cmd_verify_crl = escapeshellcmd($opensslBin) . " verify -crl_check -provider default -provider legacy -CAfile \"" . escapeshellarg($caRoot) . "\" -CRLfile \"" . escapeshellarg($crlPath) . "\" \"" . escapeshellarg($target_fileX509) . "\" 2>&1";
$revoke_result = shell_exec($cmd_verify_crl);

// Check for successful verification (looks for ": OK" in output)
if (strpos($revoke_result, ': OK') === false) {
    $reasons[] = "Certificate Revoked or Invalid: " . trim($revoke_result);  // Append output for debug
    $valid = false;
} else {
    $reasons[] = "Certificate Not Revoked";
}
*/

// Clean up temp file
@unlink($target_fileX509);

echo json_encode([
    'valid' => $valid,
    'reasons' => $reasons
]);
?>