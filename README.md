# File Manager

A single-file server panel. Upload `file_manager.php`, open it in a browser, and manage files plus the host from one place.

Made by [ANSNEW TECH.](https://inside.ansnew.com/)

## Requirements

- PHP 8.1 or newer
- Apache, Nginx with PHP-FPM, or the PHP built-in server
- The `zip` extension, only if you want archives

No Composer, database, or extra files.

## Start

1. Put `file_manager.php` on the server, preferably over HTTPS.
2. Open it in a browser.
3. Create the administrator. There is no default password.
4. Sign in. Optional two-factor authentication is in Settings.

The first run creates `.fmdata` next to the script. That folder holds the config, sessions, and the audit log. Do not publish it.

Apache and IIS rules are written for you. On Nginx, add:

```nginx
location ~ /\.fmdata/ { deny all; }
```

## What it does

- Browse, search, upload, download, edit, preview, move, copy, and delete files
- Create and extract zip archives
- Dashboard for disk, PHP, and whatever CPU and memory the host exposes
- Read-only views of processes, cron files, and logs
- A terminal that stays off until you turn it on

The file root starts as the folder that contains the script. Change it in Settings. The application file and `.fmdata` stay protected.

## Terminal

The terminal is disabled by default. Enabling it asks for your password and the word `ENABLE`.

Commands run from an allowlist, without a shell. Shells and interpreters stay blocked. Every command is written to the audit log. If the host cannot start processes, the rest of the panel still works.

## Notes

- Use HTTPS on a real server. The session cookie is marked secure only then.
- Uploads and zip extraction refuse PHP and other executable names.
- Failed sign-ins lock the account for a short time. The limits are in Settings.
- `php file_manager.php --self-test` checks the path jail, uploads, and command filter from the command line.
