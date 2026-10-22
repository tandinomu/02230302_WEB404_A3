<?php
/**
 * VULNERABLE FILE UPLOAD  —  THE WRONG WAY (for teaching only)
 *
 * It saves whatever file is uploaded, under the attacker-chosen filename,
 * into a web-accessible folder, with NO checks on:
 *   - file extension
 *   - file size
 *   - the Content-Type the browser claims
 *   - the real contents of the file
 *
 * Because the folder is under the web root, a .php file uploaded here can be
 * requested in the browser and Apache will EXECUTE it => remote code execution.
 */

$msg = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {

    $uploadDir = __DIR__ . '/uploads/';

    // basename() strips any directory part, but we still trust the attacker's
    // chosen NAME and EXTENSION — that is the core flaw.
    $name = basename($_FILES['file']['name']);
    $dest = $uploadDir . $name;

    // Move it straight in. No validation whatsoever.
    if (move_uploaded_file($_FILES['file']['tmp_name'], $dest)) {
        $msg = "Uploaded. View / run it at: "
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
  <title>Vulnerable Upload</title>
  <style>body{font-family:sans-serif;max-width:640px;margin:40px auto;line-height:1.5}</style>
</head>
<body>
  <h1>Vulnerable File Upload (INSECURE)</h1>
  <p>Uploads are saved to <code>uploads/</code> with no checks.</p>

  <form method="post" enctype="multipart/form-data">
    <input type="file" name="file" required>
    <button type="submit">Upload</button>
  </form>

  <?php if ($msg): ?><p><?= $msg ?></p><?php endif; ?>

  <p><a href="../index.php">&laquo; back</a></p>
</body>
</html>
