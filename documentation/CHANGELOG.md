# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/) and the project uses [Semantic Versioning](https://semver.org/).

## [1.1.2] - 2026-10-24

### Security
- Fixed a security issue where the visitor's IP address could be taken from a forwarding header (`X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP` and similar) that no trusted proxy had vouched for, so a visitor could appear to be someone else. The plugin now ignores the header when no trusted proxies are listed, reads the connection address instead, and shows an admin notice explaining how to fix the setup. While that fallback is active, bans and lockouts are suspended (failed logins are still logged) and rate limiting is effectively off. The WAF, User-Agent, blocklist and sensitive-file checks still apply.
- Header values that are private, loopback, link-local, carrier-grade NAT, unique-local (IPv6) or unspecified are refused. The new opt-in constant `WP_BOUNCER_ALLOW_PRIVATE_CLIENT_IPS` accepts private (not loopback) values from a trusted proxy, for intranet sites.
- Loopback requests (127.0.0.1 and ::1) are exempt only when they carry no forwarding header. Loopback and trusted-proxy addresses are never banned, and requests that carry a forwarding header from an unlisted private address (such as a local proxy you haven't listed yet) are not banned.
- Over-broad entries in Trusted proxies and the Allowlist (wider than /8 for IPv4 or /16 for IPv6, including IPv6 forms that cover all of IPv4) are ignored, and dropped on save with a message naming them.
- Fixed a security issue where an update package could come from a URL other than the expected GitHub release. The package URL must now match the expected release URL exactly.

### Changed
- The update-source filters `wp_bouncer_update_manifest_url` and `wp_bouncer_update_package_prefix` are only honoured when `WP_BOUNCER_ALLOW_UPDATE_SOURCE_FILTERS` is defined as `true` in wp-config.php. Forks and testers that relied on the filters alone must add the constant.
- Saving settings that would block the admin is refused, with a pointer to the IP setup, when the admin's address is shared (behind a proxy, CDN or the fallback), instead of allowlisting the shared address.
- Release pipeline hardening: publishing is separated from the build, actions and downloads are pinned, the zip is reproducible, and the downloaded checksum is verified.
- CI now blocks on phpcs (coding standards) and PHPStan level 6.
- Code cleaned up to WordPress Coding Standards. No change in behaviour.

### Added
- Integration tests (`make integration`) against MySQL/MariaDB, run in CI for single-site and multisite.
- End-to-end suite can run against MySQL/MariaDB and a chosen WordPress version.

## [1.1.1] - 2026-10-20

### Added
- **Sensitive-file probes** rule (`sensitive_files`). Refuses requests for files that leak secrets if they exist: `.env`, `.git/` and other version-control data, `.htpasswd`, wp-config backups, PHP file backups, database dumps, site backup archives, log files, phpinfo pages, database admin tools, known web shells, PHP in uploads, the PHPUnit `eval-stdin.php` exploit and project manifests. A file that exists is served by the web server before WordPress runs, so a probe that reaches WordPress is a guess, and the IP is banned from the whole site for 60 minutes (configurable; 0 refuses only the probe). Extra path fragments can be added. `/.well-known/` is never treated as a probe.
- **404 flood** rule (`not_found`). Bans an IP for 60 minutes after more than 20 "not found" pages in 60 seconds (all configurable). Missing images, CSS, JS, fonts and media don't count, nor do logged-in administrators or, by default, search engine crawlers.
- **No PHP in uploads** (`uploads_php`):
  - Keeps a `# BEGIN WP Bouncer` block in `wp-content/uploads/.htaccess` that refuses to run scripts there (Apache 2.2/2.4, LiteSpeed). It uses access rules only, not `php_flag`, which breaks PHP-FPM servers. Other content in the file is left alone. The block is removed when the setting is turned off, while `WP_BOUNCER_DISABLE` is on, and on deactivation and uninstall.
  - Refuses uploads through WordPress (media library, REST API, sideloads) whose names have a script extension anywhere (`photo.php.jpg`), that are server config files (`.htaccess`, `.user.ini`), or that contain `<?php`.
  - **Test now** button: puts a tiny script in uploads, requests it, deletes it, and reports whether the server ran it. The equivalent nginx rule is shown for servers that ignore `.htaccess`.
  - Safety check: after the block is written, a one-off cron job fetches a text file from uploads. If the server answers with an error (a host whose `AllowOverride` doesn't allow access rules would fail every upload, images included), the block is removed again and the admin screens say why.
- **Email alerts** (`alerts` settings, General tab). Emails when an account is created as, promoted to or given the administrator role (or made a multisite super admin), and when a plugin is installed, activated, deactivated or deleted, including WP Bouncer itself being deactivated. Plugin updates are optional (off by default). Each email says who did it, from which IP and country, and when. Changes in one request arrive as one email; at most 20 emails are sent per hour. Recipients default to the site's admin email. A **Send a test email** button. Alerts keep working while `WP_BOUNCER_DISABLE` is on.
- **Traffic log** (Traffic tab, `traffic` settings), off by default. Records every request that reaches WordPress in a new table `{prefix}bouncer_traffic`: time, IP, client type, method, URL, response code, referrer, User-Agent and logged-in user. Written on `shutdown`, so the final status is recorded, including the 403 of requests the firewall blocked. Client types (`Traffic\ClientClassifier`): browser, mobile browser, search engine, bot or crawler, uptime monitor, feed reader, WordPress, script or tool, attack tool, no User-Agent, other. Secret query parameters (`key`, `pwd`, `password`, `token`, `access_token`, `_wpnonce`, anything containing `pass`, `token` or `secret`, …) are replaced with `[removed]` in URLs and referrers. Retention 1 to 7 days (default 7), purged by an hourly cron job (`wp_bouncer_traffic_purge`). Options to skip WP-Cron and Heartbeat requests (on by default) and logged-in administrators. Filters by client, response class and IP, search, CSV export, and Block IP from any row. Summary of the last 24 hours: requests, distinct IPs, 4xx responses, top client types.
- Activity Log action `alert` (purple badge) and rule filter "Email alerts". Alerts are not counted in the Dashboard's block statistics.
- Tools → Unlock IP also lifts sensitive-file and 404-flood bans.

### Changed
- Database schema version 2 (the traffic table). Sites updating from 1.1.0 get it, and the hourly purge job, on the first request after the update.
- The three new rules and alerts are on by default, including on sites updating from 1.1.0. On update the uploads `.htaccess` block is written on the first request.
- End-to-end tests run PHP's built-in server with a router (as Apache with WordPress's rewrite rules) and pretty permalinks, and capture outgoing mail.

## [1.1.0] - 2026-10-20

### Added
- Updates from GitHub releases through WordPress's normal plugin updater. New versions show on the Plugins screen and on Dashboard → Updates with **Update now** and **View details**, and the plugin can be set to **Enable auto-updates** like any other. WP-CLI `wp plugin update` works too.
- Each update zip is checked against the SHA-256 published with the release, and must come from this repository's releases, before WordPress installs it.
- `Update URI` header, so WordPress never takes updates for this plugin from WordPress.org.
- Updates card on the Tools tab: installed and latest version, and a **Check for updates now** button.
- `WP_BOUNCER_DISABLE_UPDATES` constant to switch update checks off.
- Release workflow: pushing a `vX.Y.Z` tag runs the tests, builds the zip and `update.json`, and publishes the GitHub release.

## [1.0.1] - 2026-10-20

### Fixed
- Importing a full geo database from the Tools tab, by upload or URL, returned HTTP 500. The whole file (about 710,000 ranges) was loaded in one request, which takes from 20 seconds to a few minutes and ran past the host's PHP time limit. The import now runs in steps of about 5 seconds, driven by the Tools tab with a progress bar (`Geo\GeoImport`, `CsvImporter::prepare()` / `import_chunk()`).

- The emergency switch `WP_BOUNCER_DISABLE` didn't lift login lockouts: the firewall stopped, but the login check still refused a locked-out IP. It now turns off every blocking hook and leaves only the admin screens. A red notice is shown on every admin screen while it's on.

### Changed
- Repository split so that only the plugin is uploaded: `wp-bouncer/` (the plugin), `tests/`, `documentation/`. Some hosts' malware scanners flagged the test files, which contain attack payloads on purpose.
- `make` builds `builds/wp-bouncer-<version>.zip`, and refuses to ship any test or tooling files. `make check` runs the end-to-end suite against the installed zip, and CI does the same.
- `MemoryStore` moved from the plugin to `tests/Support`, since only the tests use it.

### Added
- Stop button for a running import. Ranges loaded so far are kept and marked "incomplete".
- "Continue import" button when JavaScript is unavailable.
- Files are checked before the current data is replaced, so a wrong file or a URL that returns an error page leaves the old data in place.
- Clear messages for uploads over `upload_max_filesize` or `post_max_size`. The Tools tab shows the server's upload limit.
- `wp_bouncer_geo_step_seconds` filter.
- End-to-end tests for the Tools-screen import, which now runs under a 30-second PHP limit.

## [1.0.0] - 2026-10-19

### Added
- Firewall core running on `plugins_loaded`, with enforce and monitor modes, an allowlist and loopback exemption.
- Rules: IP blocklist, User-Agent filter, country blocking, XML-RPC blocking, login lockout, rate limiting, WAF (SQLi/XSS/traversal/code injection), user enumeration.
- Local geolocation: DB-IP Lite / IP2Location LITE CSV import (file or URL, gzip supported), or a CDN/web-server country header.
- Admin UI: Dashboard with per-rule switches and stats, General, Rules, Countries (searchable picker grouped by continent), Activity Log (filter, search, CSV export, block IP), Tools (geo import, unlock IP).
- Guard against admins blocking themselves when saving settings.
- `wp_bouncer_rules` filter and `WP_BOUNCER_DISABLE` constant.
- PHPUnit unit suite, PHPStan config, WPCS config, end-to-end smoke test, GitHub Actions CI.
