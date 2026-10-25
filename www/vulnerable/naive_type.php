<?php
/**
 * NAIVE CONTENT-TYPE CHECK  —  LOOKS secure, ISN'T.
 *
 * It only accepts the file if $_FILES['file']['type'] is an image type.
 * The problem: that value is simply the Content-Type the CLIENT wrote into
 * the upload request. PHP copies it in as-is and never checks it against the
 * real file. So an attacker can send a .php file and just claim it is a PNG.
 *
 * (It does NOT look at the extension or the real bytes — we isolate the
 *  Content-Type lesson here. The uploads folder is web-executable.)
 */

$msg = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {

    $uploadDir   = __DIR__ . '/uploads/';
    $name        = basename($_FILES['file']['name']);
    $claimedType = $_FILES['file']['type'];          // <-- attacker-controlled!
    $allowed     = ['image/jpeg', 'image/png'];

    if (!in_array($claimedType, $allowed, true)) {
        $msg = "REJECTED: Content-Type '" . htmlspecialchars($claimedType)
             . "' is not an allowed image type.";
    } elseif (move_uploaded_file($_FILES['file']['tmp_name'], $uploadDir . $name)) {
        $msg = "ACCEPTED (claimed type '" . htmlspecialchars($claimedType)
             . "'). Saved to <a href='uploads/" . htmlspecialchars($name) . "'>uploads/"
             . htmlspecialchars($name) . "</a>";
    } else {
        $msg = "Upload failed.";
    }
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Naive Content-Type Check</title>
  <style>body{font-family:sans-serif;max-width:640px;margin:40px auto;line-height:1.5}</style>
</head>
<body>
  <h1>Naive Content-Type Check (STILL INSECURE)</h1>
  <p>Accepts the upload only if the browser-supplied <code>Content-Type</code>
     is <code>image/jpeg</code> or <code>image/png</code>.</p>

  <form method="post" enctype="multipart/form-data">
    <input type="file" name="file" required>
    <button type="submit">Upload</button>
  </form>

  <?php if ($msg): ?><p><?= $msg ?></p><?php endif; ?>

  <p><a href="../index.php">&laquo; back</a></p>
</body>
</html>
