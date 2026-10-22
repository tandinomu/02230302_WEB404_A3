<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>WEB404 A3 — File Upload Lab</title>
  <style>
    body { font-family: sans-serif; max-width: 640px; margin: 40px auto; line-height: 1.5; }
    .box { border: 1px solid #ccc; padding: 16px 20px; border-radius: 8px; margin: 16px 0; }
    .bad  { border-left: 6px solid #c0392b; }
    .good { border-left: 6px solid #27ae60; }
    code { background: #f4f4f4; padding: 1px 4px; }
  </style>
</head>
<body>
  <h1>WEB404 — Assignment 3: Secure File Upload</h1>
  <p>Local lab only (bound to <code>127.0.0.1</code>). Two versions of the same feature:</p>

  <div class="box bad">
    <h2>1. Vulnerable version</h2>
    <p>Saves any uploaded file, unchanged, into a web-accessible folder. Used to
       demonstrate the attacks.</p>
    <a href="vulnerable/index.php">Open vulnerable upload &raquo;</a>
  </div>

  <div class="box good">
    <h2>2. Secure version</h2>
    <p>Same feature, with defences: extension whitelist, magic-byte check,
       random rename, size limit, and storage outside the web root.</p>
    <a href="secure/index.php">Open secure upload &raquo;</a>
  </div>
</body>
</html>
