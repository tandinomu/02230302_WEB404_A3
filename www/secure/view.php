<?php
/**
 * SAFE RETRIEVAL of a stored upload.
 *
 * The files live OUTSIDE the web root (/var/uploads), so Apache cannot serve
 * them directly and can never execute them. This script reads a file back and
 * hands it to the browser as plain data, never as code.
 */

$storeDir = '/var/uploads';

$file = $_GET['file'] ?? '';

// Accept ONLY our own generated name shape: 32 hex characters + '.' + a
// whitelisted extension. Because this pattern allows no '/' or '..', it also
// blocks path-traversal attempts like ?file=../../etc/passwd.
if (!preg_match('/^[a-f0-9]{32}\.(jpg|jpeg|png|pdf)$/', $file)) {
    http_response_code(400);
    exit('Invalid file name.');
}

$path = $storeDir . '/' . $file;
if (!is_file($path)) {
    http_response_code(404);
    exit('Not found.');
}

// Serve with a FIXED content type derived from our own trusted extension,
// and tell the browser not to second-guess it. The file is returned as data.
$ext   = strtolower(pathinfo($file, PATHINFO_EXTENSION));
$types = ['jpg' => 'image/jpeg', 'jpeg' => 'image/jpeg',
          'png' => 'image/png',  'pdf'  => 'application/pdf'];

header('Content-Type: ' . $types[$ext]);
header('Content-Disposition: inline; filename="' . $file . '"');
header('X-Content-Type-Options: nosniff');   // disable MIME sniffing
readfile($path);
