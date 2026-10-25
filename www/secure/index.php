<?php
/**
 * SECURE FILE UPLOAD  —  layered defences (defence in depth).
 *
 * No single check is trusted on its own. In order, we enforce:
 *   1. the upload actually succeeded          (error check)
 *   2. a maximum size                          (size limit)
 *   3. an extension WHITELIST                  (allow-list, not block-list)
 *   4. the REAL content type via magic bytes   (finfo, not the client's claim)
 *   5. real content must match the extension   (no mismatch / polyglot smuggling)
 *   6. a RANDOM filename                        (discard attacker's name & path)
 *   7. storage OUTSIDE the web root            (no URL can ever execute it)
 */

// (7) Save location: /var/uploads is mounted from ./storage and is NOT under
//     /var/www/html. There is no URL that maps here, so a file saved here can
//     never be requested — and therefore never executed — by a browser.
$storeDir = '/var/uploads';

// (2) Size cap: 2 MB. Stops huge files being used to exhaust disk / memory.
$maxBytes = 2 * 1024 * 1024;

// (3) The WHITELIST. Each allowed extension is paired with the exact real MIME
//     type we will confirm from the bytes. Anything not listed is refused by
//     default — the safe default is "deny".
$allowed = [
    'jpg'  => 'image/jpeg',
    'jpeg' => 'image/jpeg',
    'png'  => 'image/png',
    'pdf'  => 'application/pdf',
];

$msg = '';
$savedName = '';   // set only on success

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {

    $f = $_FILES['file'];

    // (1) Did PHP receive the file cleanly? Catches partial/failed uploads.
    if ($f['error'] !== UPLOAD_ERR_OK) {
        $msg = 'REJECTED: upload error code ' . (int) $f['error'] . '.';

    // (2) Enforce the size limit.
    } elseif ($f['size'] > $maxBytes) {
        $msg = 'REJECTED: file is larger than 2 MB.';

    } else {
        // (3) Whitelist the extension (last extension, lower-cased).
        $ext = strtolower(pathinfo($f['name'], PATHINFO_EXTENSION));

        if (!isset($allowed[$ext])) {
            $msg = "REJECTED: extension '." . htmlspecialchars($ext)
                 . "' is not on the whitelist.";
        } else {
            // (4) Read the REAL type from the file's magic bytes. This ignores
            //     the Content-Type header and the filename completely.
            $finfo    = new finfo(FILEINFO_MIME_TYPE);
            $realMime = $finfo->file($f['tmp_name']);

            // (5) The real content must match what the extension claims.
            if ($realMime !== $allowed[$ext]) {
                $msg = "REJECTED: real content is '" . htmlspecialchars($realMime)
                     . "', which does not match a ." . htmlspecialchars($ext) . " file.";
            } else {
                // (6) Throw away the attacker-chosen name. Build our own random
                //     name and keep ONLY our trusted, whitelisted extension.
                $savedName = bin2hex(random_bytes(16)) . '.' . $ext;
                $dest      = $storeDir . '/' . $savedName;

                // (7) Move it into storage outside the web root.
                if (move_uploaded_file($f['tmp_name'], $dest)) {
                    $msg = "ACCEPTED. Stored outside the web root as: " . $savedName;
                } else {
                    $savedName = '';
                    $msg = 'Could not store the file (permissions?).';
                }
            }
        }
    }
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Secure Upload</title>
  <style>body{font-family:sans-serif;max-width:640px;margin:40px auto;line-height:1.5}
  code{background:#f4f4f4;padding:1px 4px}</style>
</head>
<body>
  <h1>Secure File Upload</h1>
  <p>Allowed: <code>jpg, jpeg, png, pdf</code>, max 2&nbsp;MB. Files are checked
     by real content, renamed randomly, and stored outside the web root.</p>

  <form method="post" enctype="multipart/form-data">
    <input type="file" name="file" required>
    <button type="submit">Upload</button>
  </form>

  <?php if ($msg): ?>
    <p><?= htmlspecialchars($msg) ?></p>
    <?php if ($savedName): ?>
      <p>Retrieve it safely: <a href="view.php?file=<?= urlencode($savedName) ?>">view.php?file=<?= htmlspecialchars($savedName) ?></a></p>
    <?php endif; ?>
  <?php endif; ?>

  <p><a href="../index.php">&laquo; back</a></p>
</body>
</html>
