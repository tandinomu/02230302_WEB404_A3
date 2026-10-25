<?php
/**
 * NAIVE EXTENSION BLACKLIST  —  LOOKS secure, ISN'T.
 *
 * It blocks a list of "dangerous" extensions. The flaw is the approach:
 *   1. You must remember EVERY executable spelling. Here we forgot .phtml.
 *   2. It only inspects the LAST extension, so it says nothing useful about
 *      tricks like double extensions.
 *
 * A whitelist ("only allow .jpg/.png/.pdf") is the correct approach, and is
 * what the secure version uses.
 */

$msg = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {

    $uploadDir = __DIR__ . '/uploads/';
    $name      = basename($_FILES['file']['name']);

    // Take the part after the last dot, lower-cased, as "the extension".
    $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));

    // The blacklist. Note: .phtml is MISSING -> that is the hole.
    $blocked = ['php', 'php3', 'php4', 'php5', 'phar'];

    if (in_array($ext, $blocked, true)) {
        $msg = "REJECTED: extension '." . htmlspecialchars($ext) . "' is blacklisted.";
    } elseif (move_uploaded_file($_FILES['file']['tmp_name'], $uploadDir . $name)) {
        $msg = "ACCEPTED (extension '." . htmlspecialchars($ext) . "'). Saved to "
             . "<a href='uploads/" . htmlspecialchars($name) . "'>uploads/"
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
  <title>Naive Extension Blacklist</title>
  <style>body{font-family:sans-serif;max-width:640px;margin:40px auto;line-height:1.5}</style>
</head>
<body>
  <h1>Naive Extension Blacklist (STILL INSECURE)</h1>
  <p>Blocks <code>.php .php3 .php4 .php5 .phar</code> &mdash; but not every
     executable spelling.</p>

  <form method="post" enctype="multipart/form-data">
    <input type="file" name="file" required>
    <button type="submit">Upload</button>
  </form>

  <?php if ($msg): ?><p><?= $msg ?></p><?php endif; ?>

  <p><a href="../index.php">&laquo; back</a></p>
</body>
</html>
