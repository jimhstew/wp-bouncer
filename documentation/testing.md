# Testing

Run all of these before deploying a change.

| Suite | Command | Needs | What it proves |
|---|---|---|---|
| Unit | `make test` | PHP 7.4+ | Rules, firewall flow, settings sanitisation, IP maths, geo parsing and chunked import (221 tests, < 1 s) |
| Static analysis | `make analyse` | `composer install` | No undefined functions or methods and no type mistakes in the WordPress-facing code (PHPStan level 5 + WordPress stubs) |
| Coding standards | `make lint` | `composer install` | WordPress Coding Standards |
| End-to-end | `make e2e` | PHP with `pdo_sqlite`, `curl`, `unzip`, internet | The plugin in a real WordPress: 73 live HTTP checks |
| Release check | `make check` | all of the above, plus `zip` | Unit tests, build the zip, then the end-to-end suite against the plugin installed **from that zip** |

The `composer test`, `composer analyse`, `composer lint` and `composer test:e2e` scripts are equivalent. Tests live in `tests/`, outside the `wp-bouncer/` plugin folder, so they never end up in the zip you upload.

CI (`.github/workflows/tests.yml`) runs the unit tests on PHP 7.4 to 8.4, builds the zip and runs the end-to-end suite against it, and runs lint.

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
│   └── FakeGeo.php          IP → country map that counts lookups
├── Unit/                    Mirrors wp-bouncer/src/
│   ├── Firewall/            FirewallTest, RequestTest, IpResolverTest
│   ├── Rules/               One test class per rule
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

`tests/e2e/run.sh` builds a disposable WordPress using the official SQLite Database Integration plugin, so no MySQL is needed. It activates WP Bouncer and switches the IP source to `X-Real-IP`, because the plugin always lets 127.0.0.1 through, and each scenario needs its own fake visitor IP. Then it checks:

- normal pages, search and the REST posts endpoint load (200)
- scanner and empty User-Agents, xmlrpc.php, `?author=1`, the REST users list, and XSS/SQLi/traversal payloads are refused (403), and the users sitemap is gone
- 5 failed logins, or one try as `admin`, lock out the IP even with the right password, while other IPs log in fine and lifting the lockout works
- the emergency switch (`WP_BOUNCER_DISABLE`) lets a locked-out IP log in and lets scanners through, and removing it restores blocking
- country blocking with the fixture geo database, site-wide and login-only
- rate limiting allows 10 requests and throttles the 11th (429)
- monitor mode lets a scanner through but logs it as `monitored`
- switching a single rule off lets its traffic through
- all six admin tabs load for an administrator with no PHP errors, and the log lists entries
- geo import through the Tools tab, the way a browser does it: upload and URL import both start, take several AJAX steps and load every range; a file that isn't a geo CSV, a URL that fails, and uploads over `upload_max_filesize` and `post_max_size` are refused with a message and leave the old data in place; the no-JavaScript Continue button and the Stop button work; the working file is cleaned up
- WordPress's `debug.log` is empty at the end

The web server runs with `max_execution_time=30`, `upload_max_filesize=2M` and `post_max_size=8M`, like typical shared hosting, so anything that needs one long request fails here as it would in production. A second built-in server on port+1 stands in for download.db-ip.com.

Options: `PHP=/path/to/php`, `WPB_E2E_ZIP=builds/wp-bouncer-1.0.1.zip` (install from a built zip instead of linking `wp-bouncer/`), `WPB_E2E_PORT=8899`, `WPB_E2E_DIR=/some/dir` (reused between runs, faster), `WPB_E2E_KEEP=1`.

## Manual checks on a staging site with MySQL

The e2e suite runs on SQLite. Before a release, also check on MySQL/MariaDB:

1. Activate, then confirm `wp_bouncer_log` and `wp_bouncer_geo` exist.
2. Tools: import the current DB-IP file by URL, and once more by uploading the .csv.gz. Each time, check that the progress bar advances, the row count is about 710k, and the import finishes in a few minutes.
3. Countries: confirm "You appear to be in …" names your country.
4. Block your own country with the scope set to login, from a second browser. The login page should be refused, and the settings save should warn that it added your IP to the allowlist.
5. Activity Log: filter, search, page through results, export CSV, use "Block IP".
6. Leave it overnight and confirm old entries are purged by the daily cron.
