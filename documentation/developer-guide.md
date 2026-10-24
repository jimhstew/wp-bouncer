# WP Bouncer developer guide

A self-contained firewall for WordPress. Like a bouncer at a club door, it checks every visitor before WordPress does any real work and turns away the ones that don't belong.

It covers most of what people install Wordfence's firewall for, but **without a cloud service, account, licence key or subscription**. Everything runs on your server, nothing about your visitors is sent anywhere, and all the code is GPL-2.0-or-later.

## Features

Every blocking rule has its own on/off switch, on the Dashboard and on the Rules tab. The Rules tab groups the rules into four categories (block lists, login and accounts, scanners and floods, attack payloads and hardening); see [rules.md](rules.md#categories-and-status).

| Rule | What it stops |
|---|---|
| **IP blocklist** | Specific IPv4/IPv6 addresses and CIDR ranges. |
| **User-Agent filter** | Known attack tools (sqlmap, Nikto, WPScan, Nuclei…), requests with no User-Agent, and your own substring or regex patterns. |
| **Country blocking** | Visitors from chosen countries, or everyone *except* chosen countries, either site-wide or only on login/XML-RPC/wp-admin. The picker lists all 249 ISO countries, grouped by continent, with search. |
| **XML-RPC blocking** | All of `xmlrpc.php`, or only the abused methods (`system.multicall` password spraying, `pingback.ping` DDoS reflection). |
| **Login lockout** | Locks out an IP after N failed logins in M minutes. Some usernames (`admin`, `root`, …) lock out on the first try. Login errors become generic so attackers can't tell which usernames exist. Works for every login path: wp-login.php, XML-RPC, REST application passwords and custom forms. |
| **Rate limiting** | Temporarily bans IPs that make too many requests (sends 429 with Retry-After). |
| **Web application firewall** | SQL injection, XSS, path traversal/file inclusion and PHP/command injection signatures in URLs, query strings, POST bodies and JSON request bodies (the JSON check skips users who can edit posts). Has per-parameter exclusions. Administrators are never inspected. |
| **User enumeration** | `?author=N` scans, the REST `/wp/v2/users` listing, and the users sitemap, for logged-out visitors. |
| **Sensitive-file probes** | Requests for `.env`, `.git/`, wp-config backups, database dumps, logs, phpinfo pages, database tools and web shells. The first probe is refused; a second within 10 minutes bans the IP site-wide for an hour (default). Probes caused by another site's page need five. |
| **404 flood** | IPs that get more than 20 "not found" pages a minute, as vulnerability scanners do. Missing images, CSS and JS, administrators and (optionally) search engine crawlers don't count. |
| **No PHP in uploads** | Scripts running from `wp-content/uploads` (a marked block in `uploads/.htaccess`), and uploads that are scripts in disguise. **Test now** checks the server really refuses. |

Also included:

- **Traffic log.** Optional: every request that reaches WordPress, with IP, client type, URL, response code, referrer, User-Agent and user, for 1 to 7 days. Secrets are removed from URLs first.
- **Email alerts.** An email when an administrator account is created or promoted, or a plugin is installed, activated, deactivated (WP Bouncer included) or deleted; optionally on plugin updates; and on risky firewall setting changes, the Activity Log being cleared, and a daily reminder while `WP_BOUNCER_DISABLE` is set (`firewall_changes`, on by default). One email per request, at most 20 an hour, each also in the Activity Log.
- **Environment checks.** PHP and database versions against their support end dates, and PHP and WordPress settings with security effects. Shown on the Dashboard tab and in Site Health. Read-only.
- **Privacy tools.** Traffic-log exporter and eraser, block-log eraser, and privacy-policy text, for WordPress's Export and Erase Personal Data tools. Erasure is by user account; there is no IP-based export.

- **Activity log.** Every block, lockout and monitored match, with time, IP, country, rule, reason, request and User-Agent. You can search and filter it, export it to CSV, and block an IP straight from a log row. For an IPv6 row, **Block /64** blocks the whole network. Entries are kept for a set number of days.
- **Dashboard.** Counts for the last 24 hours, 7 days and 30 days, a 14-day activity chart, and the top rules, IPs and countries.
- **Dashboard widget.** A WP Bouncer box on the WordPress Dashboard for users with `manage_options`, one per site (none on the network Dashboard). It shows 24-hour and 7-day block counts with trends, the top rules, IPs and countries for 7 days, and the latest blocks. Cached for 5 minutes, or an hour while the log is flooded.
- **Monitor mode.** Logs what *would* be blocked without blocking it. Use it for a few days after setup.
- **Allowlist.** IPs and ranges that skip every rule. Loopback requests (WP-Cron, same-host proxies) skip every rule only when they carry no forwarding header. Ranges wider than /8 (IPv4) or /16 (IPv6) are ignored and dropped on save.
- **Lockout protection.** If saving settings would block your own IP, your IP is added to the allowlist automatically and you're told. If your address is shared (a proxy, CDN or the IP fallback), the save is refused and you're pointed to IP detection instead. `define( 'WP_BOUNCER_DISABLE', true );` in wp-config.php switches the firewall off in an emergency.
- **Proxy/CDN support.** Reads the client IP from X-Forwarded-For, CF-Connecting-IP or X-Real-IP, but only believes those headers from proxies you list. With a header source and no trusted proxies, the header is ignored, the connection address is used, bans and lockouts are suspended, and an admin notice explains the fix. Private, loopback, link-local, CGNAT, unique-local and unspecified header values are refused; `WP_BOUNCER_ALLOW_PRIVATE_CLIENT_IPS` (wp-config.php, `true`) allows private, non-loopback values from a trusted proxy.
- **Local geolocation.** Import the free DB-IP or IP2Location LITE CSV (download by URL or upload), or use a country header your CDN already sets (Cloudflare `CF-IPCountry`, nginx/Apache GeoIP).

### What it deliberately doesn't do

Wordfence features that rely on its central service are out of scope: the real-time threat-intelligence IP feed, cloud malware signatures and the paid "Premium" rule set. Malware scanning and two-factor authentication are also out of scope. Use a dedicated plugin for those.

## Requirements

- WordPress 7.0+
- PHP 8.3+ (CI tests 8.3, 8.4 and 8.5)
- MySQL/MariaDB, or SQLite via the official SQLite Database Integration plugin

The minimums are declared in the plugin header (`Requires at least`, `Requires PHP`), `readme.txt`, `composer.json` (`require.php`), `phpcs.xml.dist` (`testVersion 8.3-`, `minimum_supported_wp_version 7.0`) and `phpstan-php83.neon`. Keep them in step. Code may use PHP 8.3 syntax and WordPress 7.0 APIs.

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
│   │   │   ├── FetchContext.php  Pure: cross-site, same-site or own request (Sec-Fetch-Site, Origin)
│   │   │   ├── IpSetupAdvisor.php  Pure: which IP-detection notice applies
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
│   │   │   ├── AtomicCounterInterface.php  Login-attempt counters (see below)
│   │   │   ├── TableCounter.php    {prefix}bouncer_counters (default for login counts)
│   │   │   ├── ObjectCacheCounter.php  Object cache, only with wp_bouncer_atomic_object_cache
│   │   │   ├── TransientStore.php  WordPress transients (uses an object cache if present)
│   │   │   └── RedactionMigration.php  DB version 3: redacts rows written by older versions
│   │   ├── Log/
│   │   │   ├── BlockLogInterface.php
│   │   │   ├── BlockLog.php    {prefix}bouncer_log reads and writes
│   │   │   ├── BudgetedBlockLog.php  Decorator: site-wide per-minute write budget
│   │   │   ├── WidgetStatsSource.php Read queries for the Dashboard widget (BlockLog implements it)
│   │   │   └── WriteBudget.php       Pure budget arithmetic
│   │   ├── Update/             Updates from GitHub releases
│   │   │   ├── Updater.php     Hooks WordPress's plugin updater; verifies the zip's SHA-256
│   │   │   └── ReleaseManifest.php  Parses and validates update.json
│   │   ├── Environment/        Read-only PHP, database and settings checks (Dashboard tab, Site Health)
│   │   ├── Privacy/PrivacyTools.php  Exporter, erasers and policy text
│   │   ├── Support/
│   │   │   ├── IpUtils.php     Validation, CIDR matching, IPv4/IPv6 encoding
│   │   │   ├── CounterSubject.php  Pure: IPv4 address or IPv6 /64 key for login counting
│   │   │   ├── UrlRedactor.php, CsvSanitizer.php  Pure: secret removal, CSV injection guard
│   │   │   └── Clock.php       Time source (frozen in tests)
│   │   └── Admin/              Admin UI
│   │   ├── AdminController.php Menu, tabs, form handlers (nonce + capability checked)
│   │   ├── FirewallCapability.php  wpb_manage_firewall (network admins on multisite)
│   │   ├── MessageCodes.php    Fixed admin notice texts, selected by code
│   │   ├── LogListTable.php    WP_List_Table for the activity log
│   │   ├── RuleCatalog.php     Pure: rule categories, slugs and the built-in rule ids in each
│   │   ├── RuleStatus.php      Pure: on/off, attention and setup flags, category totals
│   │   ├── RuleOverview.php    Assembles the grouped rule view for the Rules and Dashboard tabs
│   │   ├── RuleLabels.php      Translated titles, category names, reasons and notice text
│   │   ├── WidgetStats.php     Pure: the numbers for the Dashboard widget
│   │   ├── DashboardWidget.php Dashboard widget: capability, cache and rendering
│   │   └── views/              One PHP template per tab; rules/ has one panel per rule, partials/ the shared parts, widget.php the widget
│   ├── assets/                 admin.css, admin.js (no build step, no dependencies)
│   └── languages/              Translations
│
├── scripts/build-manifest.php  Writes update.json + release notes for a built zip. Never shipped
├── tests/                      Never shipped
│   ├── bootstrap.php           Loads wp-bouncer/src without WordPress
│   ├── Unit/                   PHPUnit tests, mirroring wp-bouncer/src/
│   ├── Support/                Test doubles: FrozenClock, MemoryStore, MemoryBlockLog, FakeGeo, FormFields (what a browser submits from a form)…
│   ├── fixtures/               Sample geo CSV; rules-non-default.php (every rule away from its default, for the Rules tab round trip)
│   └── e2e/run.sh              Real WordPress + HTTP smoke test
│
├── documentation/              Never shipped
│   ├── developer-guide.md      This file
│   ├── architecture.md, rules.md, adding-a-rule.md, geolocation.md, testing.md
│   └── CHANGELOG.md
│
├── composer.json, phpunit.xml.dist, phpcs.xml.dist, phpstan.neon.dist   Dev tooling
├── .github/workflows/tests.yml    CI: unit tests on PHP 8.3–8.5, PHPStan and phpcs (both blocking), integration tests on MySQL/MariaDB (single-site and multisite), e2e against the built zip
└── .github/workflows/release.yml  On a vX.Y.Z tag: test, build, publish the GitHub release
```

Namespaces are PSR-4: `WPBouncer\X\Y` is `wp-bouncer/src/X/Y.php`, and `WPBouncer\Tests\X\Y` is `tests/X/Y.php`.

The design rule that makes this testable: **`Firewall/`, `Rules/`, `Login/`, `Geo/CsvImporter`, `Support/`, `Settings`, `Hardening/UploadsPolicy`, `Alerts/AlertFormatter`, `Traffic/ClientClassifier`, `Traffic/TrafficEntry`, `Admin/RuleCatalog`, `Admin/RuleStatus` and `Admin/WidgetStats` never call WordPress functions.** They get everything through constructors and the `Request` object. All WordPress integration lives in `Plugin.php`, `Admin/`, `Installer.php` and the `wpdb`/transient-backed classes.

## Hooks, filters and constants

This is the public surface. WP Bouncer has no REST routes, shortcodes, blocks or WP-CLI commands of its own. The admin-post actions (`wp_bouncer_save`, `wp_bouncer_block_ip`, `wp_bouncer_geo_import` and so on), the `wp_ajax_wp_bouncer_geo_step` action and the uploads self-test are internal, check a nonce and a capability, and are not a stable API. The settings live in the option `wp_bouncer_settings`; its keys are described in [rules.md](rules.md).

### Filters

| Filter | Signature (value in → value out) | Default | Notes |
|---|---|---|---|
| `wp_bouncer_rules` | `apply_filters( 'wp_bouncer_rules', RuleInterface[] $rules, Plugin $plugin ): RuleInterface[]` | built-in chain | Add, remove or reorder rules. Entries that aren't `RuleInterface` are dropped. Runs on `plugins_loaded` priority 1. See [adding-a-rule.md](adding-a-rule.md). |
| `wp_bouncer_log_budget_per_minute` | `(int) apply_filters( …, 120 ): int` | 120 | Block-log rows written per minute, site-wide. Minimum 10. The firewall reads it at `plugins_loaded` priority 1, so add it from a mu-plugin or a plugin's main file. |
| `wp_bouncer_log_priority_budget_per_minute` | `(int) apply_filters( …, 30 ): int` | 30 | Separate allowance per minute for lockout and uploads-block rows. Minimum 5. Same timing as above. |
| `wp_bouncer_atomic_object_cache` | `(bool) apply_filters( …, false ): bool` | `false` | Keep login counters in the object cache (`wp_cache_incr()`). Only for a persistent cache shared by every web server (Redis or Memcached). Ignored unless an external object cache is in use. |
| `wp_bouncer_ipv6_wide_multiplier` | `(int) apply_filters( …, 8 ): int` | 8 | Login attempts allowed from one IPv6 /48 equal the per-/64 limit times this. Minimum 1. Read when the login guard is built. |
| `wp_bouncer_cross_site_probe_limit` | `(int) apply_filters( …, 5 ): int` | 5 | Sensitive-file probes caused by another site's page needed for a ban. Minimum 2. |
| `wp_bouncer_cross_site_404_multiplier` | `(int) apply_filters( …, 5 ): int` | 5 | Multiplier on the 404 limit for 404s caused by another site's page. Minimum 1. |
| `wp_bouncer_login_allowed_origins` | `apply_filters( 'wp_bouncer_login_allowed_origins', array() ): string[]` | `array()` | Extra origins treated as this site for login and REST credential requests. An entry is `scheme://host[:port]` (all three must match) or a bare host name (any scheme). Non-array values are ignored. Add it early (plugin main file or mu-plugin): the firewall checks origins at `plugins_loaded` priority 1. |
| `wp_bouncer_geo_import_hosts` | `(array) apply_filters( …, array( 'download.db-ip.com', 'download.ip2location.com' ) ): string[]` | the two vendor hosts | Hosts the geo URL import may download from. https only. Checked before the request and on every redirect. |
| `wp_bouncer_geo_import_allow_http` | `(bool) apply_filters( …, false ): bool` | `false` | Also allow `http://` import URLs. For local test servers only; the host list still applies. |
| `wp_bouncer_geo_max_bytes` | `(int) apply_filters( …, 1073741824 ): int` | 1 GB | Largest unpacked geo CSV the import accepts, in bytes. |
| `wp_bouncer_geo_step_seconds` | `(float) apply_filters( …, 5.0 ): float` | 5.0 | Length of each import step on the Tools tab. Lower it on hosts with very short time limits. |
| `wp_bouncer_environment_checks` | `apply_filters( …, CheckInterface[] $checks ): CheckInterface[]` | built-in checks | Add or remove environment checks. A built-in check that the filter removes stays removed. An added check implements `WPBouncer\Environment\CheckInterface`: `id(): string` (3 to 64 characters of a–z, 0–9 and `_`) and `run( EnvironmentInterface $env ): CheckResult`. Invalid and duplicate ids are dropped. |
| `wp_bouncer_update_manifest_url` | `(string) apply_filters( …, $url ): string` | `https://github.com/jimhstew/wp-bouncer/releases/latest/download/update.json` | Only applied when `WP_BOUNCER_ALLOW_UPDATE_SOURCE_FILTERS` is `true`. |
| `wp_bouncer_update_package_prefix` | `(string) apply_filters( …, $prefix ): string` | `https://github.com/jimhstew/wp-bouncer/releases/download/` | Only applied with the same constant. A package URL must equal `<prefix>v<version>/wp-bouncer-<version>.zip` exactly. |
| `wp_bouncer_waf_json_max_bytes` | `(int) apply_filters( …, $max, bool $logged_in ): int` | 1 MB for visitors who aren't logged in, 8 MB for logged-in users, each capped by `post_max_size` | Largest JSON request body the WAF inspects, in bytes. The filter receives the default (already capped) and may change it; the result is at least 1024. A larger body gets a 403. `$logged_in` says whether the user is logged in. Read on each request that has a JSON body. |
| `wp_bouncer_waf_json_max_fields` | `(int) apply_filters( …, 5000 ): int` | 5000 | Most nodes (values and containers together) in one JSON body the WAF inspects. Minimum 1. A body with more gets a 403. |
| `wp_bouncer_widget_cache_ttl` | `(int) apply_filters( …, 300 ): int` | 300 (5 minutes) | Seconds the Dashboard widget's numbers are cached, kept between 60 and 3600. A log with more than 100,000 rows in the last 14 days is always cached for an hour. |
| `wp_bouncer_rule_info` | `apply_filters( …, array(), string[] $ids ): array` | `array()` | Describes third-party rules for the Rules and Dashboard tabs: `id => array( 'category' => slug, 'title' => string )`. Built-in ids are ignored. Runs only when those tabs are built. See [adding-a-rule.md](adding-a-rule.md#give-the-rule-a-category-and-a-title-optional). |

Example: allow a headless front end to log in (in a mu-plugin, so it loads before the firewall):

```php
add_filter( 'wp_bouncer_login_allowed_origins', static function ( $origins ) {
	$origins[] = 'https://app.example.com';
	return $origins;
} );
```

### Actions

| Action | Signature | When |
|---|---|---|
| `wp_bouncer_settings_changed` | `do_action( 'wp_bouncer_settings_changed', string[] $changes, array $old, array $new )` | After a save that changed something. `$changes` are dotted key paths such as `rules.xmlrpc.enabled`; a list setting (allowlist, countries) counts as one path. `$old` and `$new` are the full settings before and after. Fired from `AdminController::save()`, which every settings write goes through. |
| `wp_bouncer_log_cleared` | `do_action( 'wp_bouncer_log_cleared' )` | After the Activity Log is emptied from its screen. The Dashboard widget drops its cached numbers. The handler then writes one audit row and sends the `firewall_changes` email when that alert is on. No arguments. |

Example: log every settings change to a site's own audit trail:

```php
add_action( 'wp_bouncer_settings_changed', static function ( array $changes, array $old, array $new ) {
	error_log( 'WP Bouncer settings changed: ' . implode( ', ', $changes ) );
}, 10, 3 );
```

### Constants (wp-config.php)

| Constant | Effect |
|---|---|
| `WP_BOUNCER_DISABLE` (`true`) | Emergency switch. Turns off every blocking hook, including login lockouts. Admin screens and email alerts keep working, and a daily reminder is sent. |
| `WP_BOUNCER_DISABLE_UPDATES` (`true`) | No update checks. |
| `WP_BOUNCER_ALLOW_UPDATE_SOURCE_FILTERS` (`true`) | Honours the two update-source filters above. For forks and tests. |
| `WP_BOUNCER_ALLOW_PRIVATE_CLIENT_IPS` (`true`) | Accepts private (not loopback) client addresses from a trusted proxy. Loopback is never accepted from a header. |
| `WP_BOUNCER_IPV6_PREFIX` (48 to 128, default 64) | Width of the IPv6 network that every per-client counter uses: login counting and lockouts, the rate limit, sensitive-file and 404 counters and bans, and the Activity Log's de-duplication. 128 means per address. |

### WordPress hooks the plugin uses

Useful when ordering your own callbacks. Priority is given where it isn't the default 10.

| Hook | Priority | What the plugin does |
|---|---|---|
| `plugins_loaded` | 0 | Schema upgrade (`Installer::maybe_upgrade`) |
| `plugins_loaded` | 1 | Firewall (`Plugin::run_firewall`) |
| `template_redirect` | 1 | Answers the users sitemap with a 404 (user-enumeration rule) |
| `template_redirect` | 999 | Counts 404s for the 404-flood rule |
| `authenticate` | 0 | Refuses cross-site logins and blocked countries before anything is counted |
| `authenticate` | 1 | Reserves a login attempt before the password is checked |
| `authenticate` | 999 | Lockouts, generic errors, country refusal backstop |
| `wp_login` | -1 | Releases a reservation for a successful login |
| `rest_authentication_errors` | 100 | Refuses application-password requests from another site, and checks lockouts and countries |
| `shutdown` | 100 | Writes the traffic-log row (`TrafficRecorder`) |
| `shutdown` | default | Sends the queued alert email (`AlertNotifier::flush`) |
| `map_meta_cap` | 10 | Maps `wpb_manage_firewall` to `manage_options` or `manage_network_options` |
| `init`, `admin_init` | default | Uploads `.htaccess` sync, log purge, alert checks, privacy policy text |
| `wp_handle_upload_prefilter`, `wp_handle_sideload_prefilter` | default | Refuses scripts in disguise |
| `wp_login_failed` | default | Counts failed logins (skipped for refused attempts) |
| `site_status_tests`, `wp_privacy_personal_data_exporters`, `wp_privacy_personal_data_erasers` | default | Site Health tests, privacy exporter and erasers |
| `wp_dashboard_setup` | default | Adds the WP Bouncer widget for users with `manage_options`. Not added on the network Dashboard. |
| `wp_bouncer_log_cleared`, `wp_bouncer_settings_changed` (the plugin's own actions) | default | The Dashboard widget drops its cached numbers. |

## Building

```bash
make            # builds/wp-bouncer-<version>.zip and its .sha256
make clean      # delete builds/
```

`make` needs only `zip` and `unzip`. If PHP is on your PATH (or given as `make PHP=/path/to/php`), it also syntax-checks every file first. The zip has a single top-level `wp-bouncer/` folder, as WordPress expects. It leaves out dotfiles, and the build fails if a test, fixture, phar or Composer file somehow ends up inside. The version in the file name comes from the `Version:` header in `wp-bouncer/wp-bouncer.php`.

## Releasing

Installed copies (1.1.0 and later) update themselves from this repository's GitHub releases, so publishing a release is how you ship.

1. Bump the version in four places: `wp-bouncer/wp-bouncer.php` (the `Version:` header and `WP_BOUNCER_VERSION`), `Plugin::VERSION`, and `readme.txt`'s `Stable tag`. Bumping it also makes browsers fetch the new admin CSS and JS instead of cached copies.
2. Add a `## [X.Y.Z] - date` section to `documentation/CHANGELOG.md`. It becomes the release notes and the "View details" changelog in wp-admin, and the build refuses to run without it. While the release is in progress, the heading is `## X.Y.Z (unreleased)`, which the build ignores; rename it to `## [X.Y.Z] - date` when you bump the version.
3. Optionally run `make check` locally.
4. Commit and push, then tag:
   ```bash
   git tag v<version>
   git push origin v<version>
   ```
5. `.github/workflows/release.yml` then runs two jobs:
   - **Build and test** checks that the tag matches the plugin version, runs the unit tests, builds the zip and `update.json` (`make manifest`), and runs the end-to-end suite against that zip.
   - **Publish the release** is a separate job that runs in the `release` GitHub environment. It publishes the GitHub release with `wp-bouncer-X.Y.Z.zip`, its `.sha256` and `update.json` attached.

   A version with a suffix (`1.2.0-beta.1`) is published as a pre-release, which installed sites ignore.

### Owner release checklist

These are one-time repository settings on GitHub. Check them before the first release, and again after changing the repository's settings or workflows.

- [ ] The `release` environment only accepts tags matching `v*`. Only the publish job uses it.
- [ ] Branch protection on the default branch requires these CI checks to pass before merging: **Coding standards (phpcs, blocking)** and **CI self-check (pins and permissions)**.
- [ ] Private vulnerability reporting is enabled, so security reports reach the maintainer privately.

Last reported status (before 1.2.0): all three are configured. The repository owner reported this, and the repository files alone don't prove it. Re-check before tagging 1.2.0.

### How updates reach sites

- The plugin header has `Update URI: https://github.com/jimhstew/wp-bouncer`. WordPress then never takes updates for it from WordPress.org. Instead it asks the `update_plugins_github.com` filter, which `Update\Updater` answers.
- `Updater` reads `https://github.com/jimhstew/wp-bouncer/releases/latest/download/update.json`. That address always points at the newest full release, and it isn't subject to GitHub's API rate limits. The answer is cached for 6 hours, or 1 hour after a failure, and "Check again" on Dashboard → Updates clears the cache. `Update\ReleaseManifest` validates the file. The zip must come from `…/releases/download/` and the SHA-256 must be present.
- Everything after that is WordPress's own updater: the notices, Update now, bulk update, auto-updates and `wp plugin update`. The one addition is `upgrader_pre_download`: `Updater` downloads our zip itself and refuses it if its SHA-256 doesn't match `update.json`, before WordPress removes the installed copy.
- The zip has a single `wp-bouncer/` folder, so the plugin keeps its folder name and stays active through updates.
- Testing and forks: the `wp_bouncer_update_manifest_url` and `wp_bouncer_update_package_prefix` filters change where updates come from, but only when `WP_BOUNCER_ALLOW_UPDATE_SOURCE_FILTERS` is defined as `true` in wp-config.php. Otherwise they are ignored. The package URL must match the expected release URL exactly. The e2e suite uses the filters with a local server. `WP_BOUNCER_DISABLE_UPDATES` switches the check off.

Do not delete or replace the assets of a published release. Sites may be part-way through updating from it. To fix a bad release, publish a new version.

## Testing before deployment

```bash
composer install

make test       # PHPUnit unit tests, under a second, no WordPress or DB needed
make analyse    # PHPStan level 6 static analysis with WordPress stubs (blocking in CI)
make lint       # WordPress Coding Standards (checks wp-bouncer/ only; blocking in CI)
make integration  # WordPress integration tests on MySQL/MariaDB (set WPB_TESTS_DB_* first)
make e2e        # Throwaway WordPress on SQLite + live HTTP checks, using wp-bouncer/ directly
make check      # unit tests, build the zip, then the e2e suite against the installed zip
```

The `composer test`, `composer analyse`, `composer lint`, `composer test:integration` and `composer test:e2e` scripts do the same.

The end-to-end script downloads WordPress, the SQLite integration plugin and WP-CLI into a temp directory. It installs the plugin, sends real benign and malicious requests through PHP's built-in server, logs into wp-admin, loads every admin tab, imports a geo database through the Tools screen, and fails if any PHP warning is logged. It needs `curl`, `unzip` and PHP with `pdo_sqlite`. To run it on MySQL or MariaDB instead, set `WPB_E2E_DB=mysql` with `WPB_E2E_DB_HOST`, `WPB_E2E_DB_USER`, `WPB_E2E_DB_PASSWORD` and `WPB_E2E_DB_NAME` (that database is dropped and recreated), and choose the WordPress version with `WPB_E2E_WP_VERSION`. See [testing.md](testing.md).

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
