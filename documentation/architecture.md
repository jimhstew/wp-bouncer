# Architecture

## The short version

```
HTTP request
   │
   ▼
WordPress loads plugins ──► wp-bouncer.php ──► Plugin::boot()   (registers hooks only)
   │
   ▼
plugins_loaded (priority 1) ──► Plugin::run_firewall()
   │
   │   Request::from_globals()        snapshot: IP (via IpResolver), method, URI, GET, POST, headers
   │   Plugin::build_rules()          10 rules, cheapest first, + "wp_bouncer_rules" filter
   │   Firewall::handle()
   │      ├─ allowlisted, or loopback with no forwarding header?  ──► let in
   │      ├─ for each enabled rule: inspect(Request) → Verdict|null
   │      │     first Verdict wins; later rules don't run
   │      ├─ log (at most once per IP+rule per 60 s)
   │      └─ enforce mode: HttpResponder::deny() → 403/429 page, exit
   │         monitor mode: carry on
   ▼
WordPress continues normally
   │
   ├─ init                       ──► UploadsGuard::maybe_sync()       keeps the uploads/.htaccess block in step with the settings
   ├─ authenticate (priority 999) ──► Plugin::filter_authenticate()   refuses locked-out IPs, generic errors
   ├─ wp_login_failed            ──► LoginGuard::record_failure()    counts, locks out, logs
   ├─ wp_handle_upload/sideload_prefilter ──► UploadsGuard::filter_upload()  refuses scripts in disguise
   ├─ template_redirect (999)    ──► Plugin::track_not_found()       counts 404s, bans floods
   ├─ user_register, set_user_role, activated_plugin, … ──► AlertNotifier   queues alert events
   ├─ shutdown                   ──► AlertNotifier::flush()           one email for everything queued, logs each event
   └─ shutdown (priority 100)    ──► TrafficRecorder::record()        one traffic row with the final status (if switched on)
```

## Layers

| Layer | Classes | Talks to WordPress? |
|---|---|---|
| Decision core | `Firewall\*`, `Rules\*`, `Login\LoginGuard`, `Settings`, `Support\*`, `Geo\CsvImporter`, `Geo\HeaderGeoProvider`, `Geo\ChainGeoProvider`, `Geo\Countries`, `Update\ReleaseManifest`, `Hardening\UploadsPolicy`, `Alerts\AlertFormatter`, `Traffic\ClientClassifier`, `Traffic\TrafficEntry` | **No.** Pure PHP, unit-tested |
| Storage adapters | `Storage\TransientStore`, `Log\BlockLog`, `Geo\GeoDatabase`, `Geo\GeoImport`, `Traffic\TrafficLog` | Yes (transients, `$wpdb`) |
| Integration | `Plugin`, `Installer`, `Admin\*`, `Update\Updater` (WordPress plugin updater, GitHub releases), `Hardening\UploadsGuard` (uploads `.htaccess`, upload checks, self-test), `Alerts\AlertNotifier` (hooks, `wp_mail`), `Traffic\TrafficRecorder` (shutdown hook, purge cron) | Yes |

Collaborators reach the core through four interfaces, each with a test double in `tests/Support/`:

- `Storage\CounterStoreInterface`: expiring counters (`Tests\Support\MemoryStore` in tests)
- `Log\BlockLogInterface`: event log (`MemoryBlockLog`)
- `Geo\GeoProviderInterface`: IP to country (`FakeGeo`)
- `Firewall\ResponderInterface`: sending the block page (`RecordingResponder`)

`Support\Clock` is substituted with `FrozenClock` so lockout and rate-limit timing can be tested exactly.

## Key decisions

**Why `plugins_loaded`?** It's the earliest hook where `is_user_logged_in()` and `current_user_can()` exist. Some rules need them, because admins skip the WAF and rate limit and logged-in users skip the user-enumeration checks. It still runs before the theme, most plugin logic, the main query and any output. A stricter alternative is PHP's `auto_prepend_file`, which Wordfence calls "extended protection". It runs before WordPress loads, but needs server configuration and can't use WordPress APIs, so it isn't done here.

**Lazy request data.** `Request` takes closures for login state, admin state and the raw body. The rules ask for them only when they need them. For example, `UserEnumerationRule` checks login state only *after* it sees `?author=N`. Ordinary page views never pay for those lookups.

**Rule order.** `Plugin::build_rules()` orders rules by cost: IP list, sensitive-file probes and the 404-flood ban check (a ban lookup each, so banned scanners are turned away before anything else), lockout check, rate limit, User-Agent, XML-RPC, user enumeration, country (one indexed DB query), WAF (regex over every parameter).

**Bans that outlast the request.** Three rules place a ban in the counter store and refuse the IP on later requests: rate limiting, sensitive-file probes and the 404 flood. The 404 flood can't be decided at `plugins_loaded`, because only WordPress's query knows whether a page exists, so `Plugin::track_not_found()` counts on `template_redirect` and `NotFoundFloodRule::inspect()` enforces the ban from the next request.

**Uploads protection works through the web server.** A script in `wp-content/uploads` is run by the web server without WordPress loading, so no PHP-side check can stop it. `UploadsGuard` writes an access rule into `uploads/.htaccess` instead, and its **Test now** probe checks the server really obeys it (nginx doesn't read `.htaccess`).

**Traffic is recorded at the very end.** The row is written on `shutdown`, when the response code is final, so it shows what the visitor really got: 200, a redirect, a 404, or the firewall's 403. The block log and the traffic log are separate tables on purpose: blocks are few and kept for weeks, while traffic is many rows and kept a week at most.

**Alerts are batched and never block.** `AlertNotifier` queues events and sends one email on `shutdown`, throttled to 20 an hour, and logs every event first. It stays registered while `WP_BOUNCER_DISABLE` is on.

**Log flood protection.** A flood of requests from one IP would otherwise mean one `INSERT` per request. `Firewall` writes at most one log row per IP+rule per 60 seconds. Every request is still blocked.

**Settings forms.** Each admin tab owns specific keys (`Settings::TAB_FIELDS`). `Settings::apply_form()` replaces only those keys, so an unticked checkbox on one tab can't change another tab's settings. Everything then passes through `Settings::sanitize()`, which allow-lists every value.

**Self-lockout guard.** Before saving, `AdminController` runs the IP-blocklist, country and User-Agent rules from the *new* settings against the admin's own request. If any of them would block it, the admin's IP is added to the allowlist and the admin is told.

**IP spoofing.** Proxy headers are only trusted when `REMOTE_ADDR` is a listed trusted proxy. If a header source is chosen but no trusted proxies are listed, the header is ignored, the connection address is used, and an admin notice offers fixes; bans and lockouts are suspended while that holds. Header values that are private, loopback, link-local, carrier-grade NAT, unique-local or unspecified are refused, unless `WP_BOUNCER_ALLOW_PRIVATE_CLIENT_IPS` is `true` (private values only, never loopback). Trusted proxy and allowlist ranges wider than /8 (IPv4) or /16 (IPv6) are ignored and dropped on save. For `X-Forwarded-For` the resolver walks right to left and takes the first hop that isn't a trusted proxy. Anything further left could have been written by the client.

## Data

| Where | What |
|---|---|
| Option `wp_bouncer_settings` | All settings (one array, autoloaded) |
| Option `wp_bouncer_geo_meta` | Row count, source and import time of the geo DB |
| Option `wp_bouncer_db_version` | Schema version for upgrades |
| Table `{prefix}bouncer_log` | Activity log. Times in UTC. Indexed on time, IP, rule. Purged daily by cron per retention setting |
| Table `{prefix}bouncer_traffic` | Traffic log, if switched on: one row per request that reached WordPress. Times in UTC. Kept 1 to 7 days, purged hourly by cron |
| Table `{prefix}bouncer_geo` | IP ranges → country. Bounds stored as 32-char hex of the 16-byte address (IPv4 mapped to `::ffff:a.b.c.d`), so string order equals address order on MySQL and SQLite alike |
| Transients `wpb_<md5>` | Failed-login counters, lockouts, rate-limit, probe and 404-flood counters and bans, log de-dup markers. All expire on their own |
| Transient `wpb_alert_count` | Alert emails sent in the current hour |
| Option `wp_bouncer_uploads_htaccess` | Fingerprint of the uploads `.htaccess` block last written, and whether that worked |
| Option `wp_bouncer_uploads_probe` | Result of the last uploads **Test now** |
| `wp-content/uploads/.htaccess` | The `# BEGIN WP Bouncer` … `# END WP Bouncer` block. Other lines in the file are never touched |

Deactivating keeps the data but removes the uploads `.htaccess` block. Deleting the plugin runs `uninstall.php`, which removes all of it.

## Extending

- `wp_bouncer_rules` filter: add, remove or reorder rules. See [adding-a-rule.md](adding-a-rule.md).
- `WP_BOUNCER_DISABLE` constant: emergency off switch.
