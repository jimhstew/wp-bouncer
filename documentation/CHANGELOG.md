# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/) and the project uses [Semantic Versioning](https://semver.org/).

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
