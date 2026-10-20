# WP Bouncer developer guide

A self-contained firewall for WordPress. Like a bouncer at a club door, it checks every visitor before WordPress does any real work and turns away the ones that don't belong.

It covers most of what people install Wordfence's firewall for, but **without a cloud service, account, licence key or subscription**. Everything runs on your server, nothing about your visitors is sent anywhere, and all the code is GPL-2.0-or-later.

## Features

Every blocking rule has its own on/off switch, on the Dashboard and on the Rules tab.

| Rule | What it stops |
|---|---|
| **IP blocklist** | Specific IPv4/IPv6 addresses and CIDR ranges. |
| **User-Agent filter** | Known attack tools (sqlmap, Nikto, WPScan, Nuclei…), requests with no User-Agent, and your own substring or regex patterns. |
| **Country blocking** | Visitors from chosen countries, or everyone *except* chosen countries, either site-wide or only on login/XML-RPC/wp-admin. The picker lists all 249 ISO countries, grouped by continent, with search. |
| **XML-RPC blocking** | All of `xmlrpc.php`, or only the abused methods (`system.multicall` password spraying, `pingback.ping` DDoS reflection). |
| **Login lockout** | Locks out an IP after N failed logins in M minutes. Some usernames (`admin`, `root`, …) lock out on the first try. Login errors become generic so attackers can't tell which usernames exist. Works for every login path: wp-login.php, XML-RPC, REST application passwords and custom forms. |
| **Rate limiting** | Temporarily bans IPs that make too many requests (sends 429 with Retry-After). |
| **Web application firewall** | SQL injection, XSS, path traversal/file inclusion and PHP/command injection signatures in URLs, query strings and POST bodies. Has per-parameter exclusions. Administrators are never inspected. |
| **User enumeration** | `?author=N` scans, the REST `/wp/v2/users` listing, and the users sitemap, for logged-out visitors. |
| **Sensitive-file probes** | Requests for `.env`, `.git/`, wp-config backups, database dumps, logs, phpinfo pages, database tools and web shells. One probe bans the IP site-wide for an hour. |
| **404 flood** | IPs that get more than 20 "not found" pages a minute, as vulnerability scanners do. Missing images, CSS and JS, administrators and (optionally) search engine crawlers don't count. |
| **No PHP in uploads** | Scripts running from `wp-content/uploads` (a marked block in `uploads/.htaccess`), and uploads that are scripts in disguise. **Test now** checks the server really refuses. |

Also included:

- **Traffic log.** Optional: every request that reaches WordPress, with IP, client type, URL, response code, referrer, User-Agent and user, for 1 to 7 days. Secrets are removed from URLs first.
- **Email alerts.** An email when an administrator account is created or promoted, or a plugin is installed, activated, deactivated (WP Bouncer included) or deleted; optionally on plugin updates. One email per request, at most 20 an hour, each also in the Activity Log.

- **Activity log.** Every block, lockout and monitored match, with time, IP, country, rule, reason, request and User-Agent. You can search and filter it, export it to CSV, and block an IP straight from a log row. Entries are kept for a set number of days.
- **Dashboard.** Counts for the last 24 hours, 7 days and 30 days, a 14-day activity chart, and the top rules, IPs and countries.
- **Monitor mode.** Logs what *would* be blocked without blocking it. Use it for a few days after setup.
- **Allowlist.** IPs and ranges that skip every rule. Loopback (WP-Cron) is always allowed.
- **Lockout protection.** If saving settings would block your own IP, your IP is added to the allowlist automatically and you're told. `define( 'WP_BOUNCER_DISABLE', true );` in wp-config.php switches the firewall off in an emergency.
- **Proxy/CDN support.** Reads the client IP from X-Forwarded-For, CF-Connecting-IP or X-Real-IP, but only believes those headers from proxies you list.
- **Local geolocation.** Import the free DB-IP or IP2Location LITE CSV (download by URL or upload), or use a country header your CDN already sets (Cloudflare `CF-IPCountry`, nginx/Apache GeoIP).

### What it deliberately doesn't do

Wordfence features that rely on its central service are out of scope: the real-time threat-intelligence IP feed, cloud malware signatures and the paid "Premium" rule set. Malware scanning and two-factor authentication are also out of scope. Use a dedicated plugin for those.

## Requirements

- WordPress 5.8+
- PHP 7.4+ (tested on 8.3)
- MySQL/MariaDB, or SQLite via the official SQLite Database Integration plugin

## Installation

See the [README](../README.md) for installing, first-time setup and recovering from a lockout.

## Repository layout

The repository is split so that only the plugin itself is ever uploaded to a server. Some hosts' malware scanners flag the test files, which are full of SQL injection and XSS payloads by design (they prove the WAF stops them). Those files live outside the plugin folder and are never packaged.

```
./
├── README.md                   Install, use and recover (for site owners)
├── Makefile                    make = build the zip; make test / analyse / lint / e2e / check
├── builds/                     Output of make: wp-bouncer-<version>.zip (+ .sha256). Not in git.
│
├── wp-bouncer/                 THE PLUGIN. Everything here ships; nothing else does.
│   ├── wp-bouncer.php          Plugin header and bootstrap (autoloader + Plugin::boot)
│   ├── uninstall.php           Drops tables, options, transients, cron and work files on delete
│   ├── readme.txt              WordPress.org-format readme
│   ├── LICENSE                 GPL-2.0
│   ├── src/                    All PHP classes
│   │   ├── Autoloader.php      Composer-free autoloader
│   │   ├── Plugin.php          Composition root: builds services, registers WP hooks
│   │   ├── Settings.php        Defaults, sanitisation, per-tab form merging
│   │   ├── Installer.php       Tables, activation/deactivation, upgrades
│   │   ├── Firewall/           The door itself
│   │   │   ├── Firewall.php    Runs rules in order, logs, enforces or monitors
│   │   │   ├── Request.php     Immutable request snapshot that rules inspect
│   │   │   ├── Verdict.php     A rule's "refuse this request" decision
│   │   │   ├── IpResolver.php  Client IP behind proxies, with spoofing protection
│   │   │   ├── ResponderInterface.php
│   │   │   └── HttpResponder.php   Sends the 403/429 block page
│   │   ├── Rules/              One class per blocking feature
│   │   │   ├── RuleInterface.php   id() / is_enabled() / inspect(Request): ?Verdict
│   │   │   ├── AbstractRule.php
│   │   │   ├── IpBlocklistRule.php
│   │   │   ├── UserAgentRule.php
│   │   │   ├── CountryRule.php
│   │   │   ├── XmlRpcRule.php
│   │   │   ├── LoginLockoutRule.php
│   │   │   ├── RateLimitRule.php
│   │   │   ├── WafRule.php
│   │   │   ├── UserEnumerationRule.php
│   │   │   ├── SensitiveFileRule.php   Bans probes for .env, .git, backups, web shells…
│   │   │   └── NotFoundFloodRule.php   Bans IPs that hit many 404s
│   │   ├── Hardening/          No PHP in uploads
│   │   │   ├── UploadsPolicy.php   Pure: .htaccess lines, nginx rule, dangerous names, PHP sniffing
│   │   │   └── UploadsGuard.php    Writes/removes the uploads/.htaccess block, checks uploads, self-test
│   │   ├── Traffic/            Optional traffic log
│   │   │   ├── ClientClassifier.php  Pure: User-Agent -> client type
│   │   │   ├── TrafficEntry.php      Pure: builds a row, removes secrets from URLs
│   │   │   ├── TrafficLog.php        {prefix}bouncer_traffic reads, writes, purge
│   │   │   └── TrafficRecorder.php   Records each request on shutdown; hourly purge
│   │   ├── Alerts/             Email alerts
│   │   │   ├── AlertFormatter.php  Pure: subject and body
│   │   │   └── AlertNotifier.php   Hooks admin/plugin changes, sends one email per request
│   │   ├── Login/LoginGuard.php    Failed-login counting and lockouts
│   │   ├── Geo/                Local IP-to-country lookup
│   │   │   ├── GeoProviderInterface.php
│   │   │   ├── GeoDatabase.php     Range table lookup
│   │   │   ├── HeaderGeoProvider.php  CDN/web-server country header
│   │   │   ├── ChainGeoProvider.php   Tries providers in order, caches per request
│   │   │   ├── CsvImporter.php     DB-IP / IP2Location CSV(.gz) parser, resumable in chunks
│   │   │   ├── GeoImport.php   Runs an import across short requests (Tools tab)
│   │   │   └── Countries.php   ISO 3166-1 list with continents
│   │   ├── Storage/            Expiring counters (lockouts, bans, rate limits)
│   │   │   ├── CounterStoreInterface.php
│   │   │   └── TransientStore.php  WordPress transients (uses an object cache if present)
│   │   ├── Log/
│   │   │   ├── BlockLogInterface.php
│   │   │   └── BlockLog.php    {prefix}bouncer_log reads and writes
│   │   ├── Update/             Updates from GitHub releases
│   │   │   ├── Updater.php     Hooks WordPress's plugin updater; verifies the zip's SHA-256
│   │   │   └── ReleaseManifest.php  Parses and validates update.json
│   │   ├── Support/
│   │   │   ├── IpUtils.php     Validation, CIDR matching, IPv4/IPv6 encoding
│   │   │   └── Clock.php       Time source (frozen in tests)
│   │   └── Admin/              Admin UI
│   │   ├── AdminController.php Menu, tabs, form handlers (nonce + capability checked)
│   │   ├── LogListTable.php    WP_List_Table for the activity log
│   │   └── views/              One PHP template per tab
│   ├── assets/                 admin.css, admin.js (no build step, no dependencies)
│   └── languages/              Translations
│
├── scripts/build-manifest.php  Writes update.json + release notes for a built zip. Never shipped
├── tests/                      Never shipped
│   ├── bootstrap.php           Loads wp-bouncer/src without WordPress
│   ├── Unit/                   PHPUnit tests, mirroring wp-bouncer/src/
│   ├── Support/                Test doubles: FrozenClock, MemoryStore, MemoryBlockLog, FakeGeo…
│   ├── fixtures/               Sample geo CSV
│   └── e2e/run.sh              Real WordPress + HTTP smoke test
│
├── documentation/              Never shipped
│   ├── developer-guide.md      This file
│   ├── architecture.md, rules.md, adding-a-rule.md, geolocation.md, testing.md
│   └── CHANGELOG.md
│
├── composer.json, phpunit.xml.dist, phpcs.xml.dist, phpstan.neon.dist   Dev tooling
├── .github/workflows/tests.yml    CI: unit tests on PHP 7.4–8.4, e2e against the built zip, lint
└── .github/workflows/release.yml  On a vX.Y.Z tag: test, build, publish the GitHub release
```

Namespaces are PSR-4: `WPBouncer\X\Y` is `wp-bouncer/src/X/Y.php`, and `WPBouncer\Tests\X\Y` is `tests/X/Y.php`.

The design rule that makes this testable: **`Firewall/`, `Rules/`, `Login/`, `Geo/CsvImporter`, `Support/`, `Settings`, `Hardening/UploadsPolicy`, `Alerts/AlertFormatter`, `Traffic/ClientClassifier` and `Traffic/TrafficEntry` never call WordPress functions.** They get everything through constructors and the `Request` object. All WordPress integration lives in `Plugin.php`, `Admin/`, `Installer.php` and the `wpdb`/transient-backed classes.

## Building

```bash
make            # builds/wp-bouncer-<version>.zip and its .sha256
make clean      # delete builds/
```

`make` needs only `zip` and `unzip`. If PHP is on your PATH (or given as `make PHP=/path/to/php`), it also syntax-checks every file first. The zip has a single top-level `wp-bouncer/` folder, as WordPress expects. It leaves out dotfiles, and the build fails if a test, fixture, phar or Composer file somehow ends up inside. The version in the file name comes from the `Version:` header in `wp-bouncer/wp-bouncer.php`.

## Releasing

Installed copies (1.1.0 and later) update themselves from this repository's GitHub releases, so publishing a release is how you ship.

1. Bump the version in four places: `wp-bouncer/wp-bouncer.php` (the `Version:` header and `WP_BOUNCER_VERSION`), `Plugin::VERSION`, and `readme.txt`'s `Stable tag`. Bumping it also makes browsers fetch the new admin CSS and JS instead of cached copies.
2. Add a `## [X.Y.Z] - date` section to `documentation/CHANGELOG.md`. It becomes the release notes and the "View details" changelog in wp-admin, and the build refuses to run without it.
3. Optionally run `make check` locally.
4. Commit and push, then tag:
   ```bash
   git tag v1.1.1
   git push origin v1.1.1
   ```
5. `.github/workflows/release.yml` then:
   - checks that the tag matches the plugin version
   - runs the unit tests
   - builds the zip and `update.json` (`make manifest`)
   - runs the end-to-end suite against that zip
   - publishes the GitHub release with `wp-bouncer-X.Y.Z.zip`, its `.sha256` and `update.json` attached

   A version with a suffix (`1.2.0-beta.1`) is published as a pre-release, which installed sites ignore.

### How updates reach sites

- The plugin header has `Update URI: https://github.com/jimhstew/wp-bouncer`. WordPress 5.8+ then never takes updates for it from WordPress.org. Instead it asks the `update_plugins_github.com` filter, which `Update\Updater` answers.
- `Updater` reads `https://github.com/jimhstew/wp-bouncer/releases/latest/download/update.json`. That address always points at the newest full release, and it isn't subject to GitHub's API rate limits. The answer is cached for 6 hours, or 1 hour after a failure, and "Check again" on Dashboard → Updates clears the cache. `Update\ReleaseManifest` validates the file. The zip must come from `…/releases/download/` and the SHA-256 must be present.
- Everything after that is WordPress's own updater: the notices, Update now, bulk update, auto-updates and `wp plugin update`. The one addition is `upgrader_pre_download`: `Updater` downloads our zip itself and refuses it if its SHA-256 doesn't match `update.json`, before WordPress removes the installed copy.
- The zip has a single `wp-bouncer/` folder, so the plugin keeps its folder name and stays active through updates.
- Testing and forks: the `wp_bouncer_update_manifest_url` and `wp_bouncer_update_package_prefix` filters change where updates come from. The e2e suite uses them with a local server. `WP_BOUNCER_DISABLE_UPDATES` switches the check off.

Do not delete or replace the assets of a published release. Sites may be part-way through updating from it. To fix a bad release, publish a new version.

## Testing before deployment

```bash
composer install

make test       # 422 PHPUnit unit tests, under a second, no WordPress or DB needed
make analyse    # PHPStan static analysis with WordPress stubs
make lint       # WordPress Coding Standards (checks wp-bouncer/ only)
make e2e        # Throwaway WordPress on SQLite + live HTTP checks, using wp-bouncer/ directly
make check      # unit tests, build the zip, then the e2e suite against the installed zip
```

The `composer test`, `composer analyse`, `composer lint` and `composer test:e2e` scripts do the same.

The end-to-end script downloads WordPress, the SQLite integration plugin and WP-CLI into a temp directory. It installs the plugin, sends real benign and malicious requests through PHP's built-in server, logs into wp-admin, loads every admin tab, imports a geo database through the Tools screen, and fails if any PHP warning is logged. It needs `curl`, `unzip` and PHP with `pdo_sqlite`. See [testing.md](testing.md).

## Documentation

- [architecture.md](architecture.md): request lifecycle, design decisions, data storage
- [rules.md](rules.md): every rule and its settings, with false-positive notes
- [adding-a-rule.md](adding-a-rule.md): writing a new rule (in the plugin or from another plugin)
- [geolocation.md](geolocation.md): geo database sources, formats, licensing, how imports run
- [testing.md](testing.md): test layout and how to run each suite
- [CHANGELOG.md](CHANGELOG.md)

## Licence

GPL-2.0-or-later. See [wp-bouncer/LICENSE](../wp-bouncer/LICENSE).

If you use the DB-IP Lite database, its CC BY 4.0 licence asks for attribution, e.g. "IP Geolocation by DB-IP" linking to https://db-ip.com, somewhere on your site.
