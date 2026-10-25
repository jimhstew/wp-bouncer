# Testing

Run all of these before deploying a change.

| Suite | Command | Needs | What it proves |
|---|---|---|---|
| Unit | `make test` | PHP 8.3+ | Rules, firewall flow, settings sanitisation, IP maths, geo parsing and chunked import, update manifest validation, uploads policy, alert wording, client types, URL redaction, rule categories and status, and widget numbers (under 1 s) |
| Static analysis | `make analyse` | `composer install` | No undefined functions or methods and no type mistakes in the WordPress-facing code (PHPStan level 6 + WordPress stubs). Blocking in CI. |
| Coding standards | `make lint` | `composer install` | WordPress Coding Standards. Blocking in CI. |
| Integration | `make integration` | `composer install`, PHP with `mysqli`, a MySQL or MariaDB server | The plugin inside the WordPress test library, on a real database, single-site and multisite (CI) |
| End-to-end | `make e2e` | PHP with `pdo_sqlite`, `curl`, `unzip`, internet (or MySQL/MariaDB with `WPB_E2E_DB=mysql`) | The plugin in a real WordPress, through live HTTP requests |
| Release check | `make check` | all of the above, plus `zip` | Unit tests, build the zip, then the end-to-end suite against the plugin installed **from that zip** |

The `composer test`, `composer analyse`, `composer lint`, `composer test:integration` and `composer test:e2e` scripts are equivalent. Tests live in `tests/`, outside the `wp-bouncer/` plugin folder, so they never end up in the zip you upload.

CI (`.github/workflows/tests.yml`) runs the unit tests on PHP 8.3, 8.4 and 8.5, PHPStan (level 6, `phpstan.neon.dist`) and phpcs, which both block, the integration suite on MySQL and MariaDB in single-site and multisite, and builds the zip and runs the end-to-end suite against it. The integration and end-to-end jobs use WordPress 7.0, latest, and nightly; nightly is allowed to fail.

## Unit tests

```
tests/
├── bootstrap.php            Defines ABSPATH and registers the autoloaders. No WordPress.
├── Support/                 Test doubles
│   ├── Requests.php         Requests::make([...]) builds a Request in one line
│   ├── FrozenClock.php      Time that only moves when the test advances it
│   ├── MemoryBlockLog.php   Captures log entries for assertions
│   ├── MemoryStore.php      In-memory counter store (lockouts, bans, rate limits)
│   ├── RecordingResponder.php  Captures deny() calls instead of exiting
│   ├── FakeGeo.php          IP → country map that counts lookups
│   └── FormFields.php       Works out what a browser would submit from a form (the Rules tab round trip)
├── Unit/                    Mirrors wp-bouncer/src/
│   ├── Firewall/            FirewallTest, RequestTest, IpResolverTest
│   ├── Rules/               One test class per rule, with must-block and must-pass lists
│   ├── Hardening/           UploadsPolicyTest (dangerous names, PHP sniffing, .htaccess, probe results)
│   ├── Admin/               RuleCatalogTest, RuleStatusTest, WidgetStatsTest (categories, status flags, widget numbers)
│   ├── Alerts/              AlertFormatterTest (subject, body, header injection, de-duplication)
│   ├── Traffic/             ClientClassifierTest, TrafficEntryTest (rows, secrets removed, status filters)
│   ├── Update/              ReleaseManifestTest
│   ├── Login/               LoginGuardTest (also covers LoginLockoutRule)
│   ├── Geo/                 CsvImporterTest, GeoProvidersTest, CountriesTest
│   ├── Log/                 BlockLogTest (row normalisation, CSV-injection guard)
│   ├── Support/             IpUtilsTest, MemoryStoreTest
│   └── SettingsTest.php
└── fixtures/geo-sample.csv
```

Conventions:
- Every attack signature has a **must-block** case and the WAF has a list of **must-pass** prose (`WafRuleTest::harmless()`). When you tune a signature, add both.
- Time-based behaviour (lockout expiry, rate-limit windows, log de-dup) is tested by advancing `FrozenClock`, never with `sleep()`.
- Run one file: `vendor/bin/phpunit tests/Unit/Rules/WafRuleTest.php`. Filter: `--filter test_blocks_attack_payloads`.
- Coverage: `composer test:coverage` (needs Xdebug or PCOV). It writes `builds/coverage/`.

## End-to-end

`tests/e2e/run.sh` builds a disposable WordPress using the official SQLite Database Integration plugin by default, so no MySQL is needed. It activates WP Bouncer and switches the IP source to `X-Real-IP` with 127.0.0.1 listed as the trusted proxy. A loopback request is exempt only when it carries no forwarding header, so the test's requests from 127.0.0.1 are still inspected. Each scenario sends its own fake visitor IP in `X-Real-IP`. Then it checks:

- normal pages, search and the REST posts endpoint load (200)
- scanner and empty User-Agents, xmlrpc.php, `?author=1`, the REST users list, and XSS/SQLi/traversal payloads are refused (403), and the users sitemap is gone
- 5 failed logins, or one try as `admin`, lock out the IP even with the right password, while other IPs log in fine and lifting the lockout works
- updates, with a local server standing in for GitHub releases: no update offered at the same version and the auto-update toggle is offered; a newer release appears on the Plugins screen, Dashboard → Updates and View details; a zip whose SHA-256 doesn't match is refused and the old version keeps running; **Update now** and an auto-update (run as WP-Cron runs it) install the new version, which stays active, keeps its settings and keeps blocking; `WP_BOUNCER_DISABLE_UPDATES` turns the check off. The test replaces the linked source folder with a copy first, because an update deletes the installed folder.
- the emergency switch (`WP_BOUNCER_DISABLE`) lets a locked-out IP log in and lets scanners through, and removing it restores blocking
- country blocking with the fixture geo database, site-wide and login-only
- rate limiting allows 10 requests and throttles the 11th (429)
- monitor mode lets a scanner through but logs it as `monitored`
- switching a single rule off lets its traffic through
- sensitive-file probes (`/.env`, `/.git/config`, `wp-config.php.bak`, `backup.zip`, PHPUnit's `eval-stdin.php`): the first is refused and doesn't ban; a second from the same visitor bans the IP from every page; other IPs are unaffected; probes sent with `Sec-Fetch-Site: cross-site` need five before anything is banned, and then only that visitor's cross-site requests are refused; `/.well-known/` is left alone; a ban of 0 minutes refuses only the probe; and an administrator is never banned
- the 404 flood: six "not found" pages are answered normally and the seventh request is refused; missing images and Googlebot don't count; a few typos are fine
- no PHP in uploads: the `.htaccess` block is written and survives the after-write check; on a stand-in host that answers every upload with a 500 while the block is there, the check removes it, doesn't rewrite it, logs it and warns the admin, **Test now** reports it, and **Write it now** restores it once the host is fixed; **Test now** reports protected (and not protected once the block is switched off), the owner's own lines in that file survive every change, the block is removed while `WP_BOUNCER_DISABLE` is on and on deactivation, and comes back afterwards; `photo.php.jpg` and a GIF containing PHP are refused through WP-CLI `media import` and the REST API, while a real image uploads
- email alerts (captured through `pre_wp_mail`): a new administrator, a promotion and an added administrator role each send one email, a new subscriber and a demotion send none; plugin activate, deactivate, install (+ activate, as one email) and delete; WP Bouncer's own deactivation; **Send a test email**; custom recipients; alerts while `WP_BOUNCER_DISABLE` is on; the 20-an-hour limit (logged but not emailed); alerts switched off; a plugin update with update alerts on
- the traffic log: off by default; once on, it records a page view with its referrer and User-Agent, a 404, a redirect, a request the firewall blocked (403), the client types of a browser, Googlebot, curl and an empty User-Agent, and a logged-in admin's user ID; a password-reset key never reaches the table; WP-Cron is skipped unless asked; the Traffic tab lists rows, filters by client, response class and IP, exports CSV with the filter applied, saves its settings and clears the log; skipping administrators works; the hourly purge keeps 7 days, then 1 day, and never more than 7 days; switched off, nothing is recorded
- all seven admin tabs load for an administrator with no PHP errors, and the log lists entries
- **WAF JSON bodies**: a SQL injection or `<script>` in a JSON body is refused (403), a benign body passes, a JSON payload under `text/plain` or in a content-type list is refused, a body nested past 512 levels is refused, broken JSON gets core's 400 (no WAF verdict), an editor's HTML and code saves over REST pass while a subscriber's are refused, an application-password editor is exempt only on REST, and a body padded past 1 MB is refused for an anonymous visitor
- **Dashboard widget**: renders for an administrator without JavaScript, and escapes hostile values in log columns
- **Rules tab** (section "Rules tab"): the round trip (render, submit as a browser does without JavaScript, save: nothing changes), one field changed alters only that field, one anchor per rule and category, `wpb_rule` opens its panel, the uploads notice links to its rule, and the Dashboard still toggles a rule
- geo import through the Tools tab, the way a browser does it: upload and URL import both start, take several AJAX steps and load every range; a file that isn't a geo CSV, a URL that fails, and uploads over `upload_max_filesize` and `post_max_size` are refused with a message and leave the old data in place; the no-JavaScript Continue button and the Stop button work; the working file is cleaned up
- WordPress's `debug.log` is empty at the end

The web server runs with `max_execution_time=30`, `upload_max_filesize=2M` and `post_max_size=8M`, like typical shared hosting, so anything that needs one long request fails here as it would in production. It has four workers, so the site can request itself (the uploads test does). A router script makes it behave like Apache with WordPress's rewrite rules (files that exist are served, everything else goes to WordPress) and, while WP Bouncer's block is in `uploads/.htaccess`, refuses scripts in uploads the way Apache would. OPcache is on, with timestamp validation on every request, so the update tests can swap the linked plugin folder for a copy and still see the new files. The site uses pretty permalinks. A second built-in server on port+1 stands in for download.db-ip.com.

Options: `PHP=/path/to/php`, `WPB_E2E_ZIP=builds/wp-bouncer-<version>.zip` (install from a built zip instead of linking `wp-bouncer/`), `WPB_E2E_PORT=8899`, `WPB_E2E_DIR=/some/dir` (reused between runs, faster), `WPB_E2E_KEEP=1`.

Database and WordPress version:

- `WPB_E2E_DB=sqlite` (default) or `mysql`. The `mysql` setting covers MariaDB too.
- `WPB_E2E_DB_HOST` (default `127.0.0.1`, may include a port), `WPB_E2E_DB_USER` (default `root`, needs CREATE and DROP on the database), `WPB_E2E_DB_PASSWORD` (default empty), `WPB_E2E_DB_NAME` (default `wpb_e2e`). The database is **dropped and recreated**, so use a disposable one. The name may only contain letters, digits and `_`.
- `WPB_E2E_WP_VERSION=latest` (default), `nightly`, or a version such as `7.0`. Versions below 7.0 are not supported by the plugin.
- `WPB_E2E_CACHE=dir` (default `builds/e2e-cache/`, git-ignored). WordPress, wp-cli and the SQLite plugin are downloaded once and reused. Every cached file is checked against its checksum each time it is used and fetched again on a mismatch, so a corrupted cache never passes. WordPress is cached per version; `latest` is resolved through api.wordpress.org first (offline, the newest cached release is used), and `nightly` is reused for 3 hours. CI caches this folder for the e2e jobs; the release workflow does not.
- `WPB_E2E_ONLY="Updates,Traffic"` runs setup plus only the sections whose `==> ` heading contains one of the comma-separated words (case-insensitive). For local debugging; CI never sets it. The run prints that it was partial and which sections ran, and the pass/fail summary works as usual. "Emergency switch" runs "Brute-force protection" first and "Admin screens" runs "Bad visitors" first; the other sections stand alone, but a few counts (such as the Activity Log entries) assume the whole suite ran. An unknown word is an error that lists the section names.

Example, against a local MariaDB:

```bash
WPB_E2E_DB=mysql WPB_E2E_DB_USER=root WPB_E2E_DB_PASSWORD=root WPB_E2E_WP_VERSION=7.0 make e2e
```

## Integration tests

`make integration` runs the PHPUnit suite in `tests/Integration/` inside the WordPress test library, against a real MySQL or MariaDB database. It covers what the unit tests can't: the installer, the block log, the traffic log and its recorder, geo database and import, the uploads guard, alerts, the updater, uninstall, the WordPress hooks in `PluginTest`, and the admin screens and self-lockout guard. Also the Rules tab (`Integration/Admin/RulesTabTest`): its markup and deep links, third-party rows, the Dashboard overview, and the round trip. The round trip renders the form, submits it the way a browser does, and checks that saving changes no setting. It runs with defaults and with `tests/fixtures/rules-non-default.php`, where every rule is set away from its default. Also the Dashboard widget, privacy tools, and the settings audit (`ConfigurationAuditTest`, including the alert when log retention is lowered; `Audit/SettingsAuditorTest` for settings written outside the admin UI, including a switched-blog write on multisite).

| Variable | Default | Meaning |
|---|---|---|
| `WPB_TESTS_DB_HOST` | `127.0.0.1` | MySQL/MariaDB host, may include a port (`127.0.0.1:3307`) |
| `WPB_TESTS_DB_USER` | `root` | Database user |
| `WPB_TESTS_DB_PASSWORD` | empty | Database password |
| `WPB_TESTS_DB_NAME` | `wpb_tests` | Database name. Use a disposable database. |
| `WP_VERSION` | `latest` | WordPress version for the test library, for example `7.0`. Set on the command line, as in `make integration WP_VERSION=7.0`. |

On the first run, `tests/Integration/install-wp.sh` downloads the WordPress test library into `builds/wp-core/<version>`. Set `WP_MULTISITE=1` to run the suite as a multisite network. CI runs single-site and multisite on MySQL 8.4 and MariaDB 10.11 and 11.4.

No integration test reaches the network. Every outbound HTTP request is answered locally with a 503 (`PluginHelpers::wpb_block_http()`) unless the test fakes that request itself. Tests that need real DDL call `use_real_ddl()` and rebuild the schema afterwards.

Example:

```bash
WPB_TESTS_DB_HOST=127.0.0.1 WPB_TESTS_DB_USER=root WPB_TESTS_DB_PASSWORD=root make integration
```

## Manual checks on a staging site with MySQL

The e2e suite runs on SQLite by default, and CI runs it on MySQL/MariaDB too (see "Database and WordPress version" above). Before a release, also check on MySQL/MariaDB:

1. Activate, then confirm `wp_bouncer_log`, `wp_bouncer_geo`, `wp_bouncer_traffic` and `wp_bouncer_counters` exist.
2. Tools: import the current DB-IP file by URL, and once more by uploading the .csv.gz. Each time, check that the progress bar advances, the row count is about 710k, and the import finishes in a few minutes.
3. Countries: confirm "You appear to be in …" names your country.
4. Block your own country with the scope set to login, from a second browser. The login page should be refused, and the settings save should warn that it added your IP to the allowlist.
5. Activity Log: filter, search, page through results, export CSV, use "Block IP".
6. Leave it overnight and confirm old entries are purged by the daily cron.
7. On Apache or LiteSpeed: **Rules → No PHP in uploads → Test now** reports Protected. On nginx, add the rule shown there, reload nginx, and test again.
8. **General → Email alerts → Send a test email** arrives through the site's real mail setup.
9. Upgrade: on a copy of a 1.1.x site, update to this build. Check that the option `wp_bouncer_db_version` is 3, that `wp_bouncer_counters` exists, that the traffic table has its `user_id` index, and that the redaction finishes (the option `wp_bouncer_migration_3` is deleted) within a few minutes of cron running.
10. Rules tab with JavaScript and assistive technology (hash opening, focus, `invalid` fields, unsaved-change text, keyboard and screen readers, RTL, high contrast): work through [architecture/rules-ui-checklist.md](architecture/rules-ui-checklist.md) before tagging 1.2.0. No automated suite covers these behaviours.

## WPB-10b manual checks

Resizable columns on Activity Log and Traffic. Chrome, Firefox and Safari; no automated browser test covers these. Record the result in the PR.

- Drag a handle: the column widens and narrows live, with no overlap and no horizontal page scroll.
- Arrow Left/Right on a focused handle changes the width by a small step; Shift+Arrow by a large step.
- Home sets the minimum width, End the maximum; Esc restores the width from before the drag or key press.
- Double-click a handle: that column returns to its default width.
- Reset button: appears once a width is changed, resets that table only, then hides again.
- Click a header label: the table sorts. Press and release on the handle: it never sorts.
- Click just beside the handle (edge of the label): sorts, and does not start a drag.
- Reload: the widths are kept.
- Resize `Request` on Log, then open Traffic: its `Request` column keeps its own width, and a Log reset leaves Traffic's width alone.
- At 782px or narrower: no handles, auto table layout, long values still clip.
- RTL (site language he_IL): handles on the left edge, drag and arrow directions mirrored.
- Forced colors (Windows contrast theme or Chrome emulation): handle and its focus ring are visible.
- Hostile storage: in devtools set `localStorage['wpb_cols:log:request']` to `<img src=x onerror=alert(1)>`, `-5`, `1e9`, `{` and `12px;background:url(//x)`, then reload. No dialog, no request, layout is sane.
- With `Storage.prototype.setItem` throwing, dragging still works for the session and nothing errors.
