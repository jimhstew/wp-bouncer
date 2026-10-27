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
   │      ├─ log (at most once per IP+rule, or per IPv6 /64, per 60 s)
   │      └─ enforce mode: HttpResponder::deny() → 403/429 page, exit
   │         monitor mode: carry on
   ▼
WordPress continues normally
   │
   ├─ init                       ──► UploadsGuard::maybe_sync()       keeps the uploads/.htaccess block in step with the settings
   ├─ authenticate (0 / 1 / 999)  ──► Plugin::screen_login_attempt()  refuses cross-site and blocked-country logins
   │                              Plugin::reserve_login_attempt()  counts the attempt before the password check
   │                              Plugin::filter_authenticate()    refuses locked-out IPs, generic errors
   ├─ wp_login_failed            ──► LoginGuard::record_failure()    counts, locks out, logs
   ├─ wp_login / application_password_did_authenticate (20) ──► AdminLoginRecorder   admin login row, location check, alert (see architecture/admin-logins.md)
   ├─ wp_handle_upload/sideload_prefilter ──► UploadsGuard::filter_upload()  refuses scripts in disguise
   ├─ template_redirect (999)    ──► Plugin::track_not_found()       counts 404s, bans floods
   ├─ user_register, set_user_role, activated_plugin, … ──► AlertNotifier   queues alert events
   ├─ shutdown                   ──► AlertNotifier::flush()           one email for everything queued, logs each event
   └─ shutdown (priority 100)    ──► TrafficRecorder::record()        one traffic row with the final status (if switched on)
```

## Layers

| Layer | Classes | Talks to WordPress? |
|---|---|---|
| Decision core | `Firewall\*` (including `FetchContext`, `IpSetupAdvisor`), `Rules\*`, `Login\LoginGuard`, `Settings`, `SettingsDiff`, `Audit\SettingsChange` and `Audit\AuditActor` (settings audit, see [settings-audit](architecture/settings-audit.md)), `AdminLogins\LocationHistory`, `LoginLocationPolicy`, `LoginAssessment` and `LoginEvent` (admin logins, see [admin-logins](architecture/admin-logins.md)), `Support\*` (including `CounterSubject`, `UrlRedactor`, `CsvSanitizer`), `Log\WriteBudget`, `Geo\CsvImporter`, `Geo\HeaderGeoProvider`, `Geo\ChainGeoProvider`, `Geo\Countries`, `Geo\GeoUrlPolicy`, `Update\ReleaseManifest`, `Hardening\UploadsPolicy`, `Alerts\AlertFormatter`, `Traffic\ClientClassifier`, `Traffic\TrafficEntry`, `Environment\*` checks and `Environment\SupportPolicy`, `Admin\RuleCatalog` (rule categories), `Admin\RuleStatus` (the one status every screen reads) and `Admin\WidgetStats` (widget numbers) | **No.** Pure PHP, unit-tested |
| Storage adapters | `Storage\TransientStore`, `Storage\TableCounter`, `Storage\ObjectCacheCounter`, `Storage\RedactionMigration`, `Log\BlockLog`, `Geo\GeoDatabase`, `Geo\GeoImport`, `Traffic\TrafficLog`, `AdminLogins\LoginHistoryRepository` (user options) | Yes (transients, object cache, `$wpdb`) |
| Integration | `Plugin`, `Installer`, `Admin\*`, `Update\Updater` (WordPress plugin updater, GitHub releases), `Hardening\UploadsGuard` (uploads `.htaccess`, upload checks, self-test), `Alerts\AlertNotifier` (hooks, `wp_mail`), `Admin\RuleOverview` (gathers the facts and runs `wp_bouncer_rule_info`), `Admin\RuleLabels` (translated text), `Admin\DashboardWidget` (capability and transient cache), `Traffic\TrafficRecorder` (shutdown hook, purge cron), `Log\BudgetedBlockLog` (decorator around `BlockLog`), `Privacy\PrivacyTools` (exporter, erasers, policy text), `Privacy\AdminLoginPrivacy` (admin-login exporter and eraser), `AdminLogins\AdminLoginRecorder` (login hooks, never refuses anyone), `Audit\SettingsAuditor` (option hooks: audits every `wp_bouncer_settings` write, UI or not), `Environment\EnvironmentAdmin` and `SiteHealth` | Yes |

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

**Bans that outlast the request.** Three rules place a ban in the counter store and refuse the IP on later requests: rate limiting, sensitive-file probes and the 404 flood. The 404 flood can't be decided at `plugins_loaded`, because only WordPress's query knows whether a page exists, so `Plugin::track_not_found()` counts on `template_redirect` and `NotFoundFloodRule::inspect()` enforces the ban from the next request. Automatic bans and lockouts are capped at 24 hours. A sensitive-file probe bans on the second hit within 10 minutes, not the first.

**Requests from another site.** A browser's `Sec-Fetch-Site` header (or, on older browsers, `Origin`) says whether a request was started by another site. `Firewall\FetchContext` classifies it, and `Request` exposes the result. Login posts that another site started are refused before the password check, so forged headers get no guesses. A probe or 404 caused by another site's page has its own, higher limit and can only refuse that visitor's requests from other sites. Nothing caused by another site can place a site-wide ban.

**Login counting.** Each login attempt is reserved in an atomic counter before the password check (`authenticate` priority 1). A successful login releases the reservation on `wp_login` (or `application_password_did_authenticate` for application passwords). A failure keeps the reservation as the counted failure: `wp_login_failed` settles it through `LoginGuard::record_failure()` and doesn't count it a second time. The counter is `Storage\TableCounter` (`{prefix}bouncer_counters`) unless a shared object cache is declared through `wp_bouncer_atomic_object_cache`. Keys use `Support\CounterSubject`: the IPv4 address, or the IPv6 /64 network (`WP_BOUNCER_IPV6_PREFIX`). The rate limit, sensitive-file and 404 rules and the log's de-duplication use the same subject.

**Uploads protection works through the web server.** A script in `wp-content/uploads` is run by the web server without WordPress loading, so no PHP-side check can stop it. `UploadsGuard` writes an access rule into `uploads/.htaccess` instead, and its **Test now** probe checks the server really obeys it (nginx doesn't read `.htaccess`).

**Traffic is recorded at the very end.** The row is written on `shutdown`, when the response code is final, so it shows what the visitor really got: 200, a redirect, a 404, or the firewall's 403. The block log and the traffic log are separate tables on purpose: blocks are few and kept for weeks, while traffic is many rows and kept a week at most.

**Alerts are batched and never block.** `AlertNotifier` queues events and sends one email on `shutdown`, throttled to 20 an hour, and logs every event first. It stays registered while `WP_BOUNCER_DISABLE` is on.

**Admin logins (1.3.0).** Successful admin logins are rows in the same log (action `login`, rule `admin_login`), not a new table. They are matched to a user by the fixed `User ID N:` prefix of `reason`, so there is no `user_id` column. A per-site location history in user meta drives a "new location" email. Login rows are never threats: `BlockLog::NON_THREAT_ACTIONS` keeps them out of counts. See [admin-logins](architecture/admin-logins.md).

**Log flood protection.** A flood of requests from one IP would otherwise mean one `INSERT` per request. `Firewall` writes at most one log row per IP+rule per 60 seconds (per /64 network for IPv6), and a site-wide write budget (`Log\WriteBudget`, 120 rows a minute by default, with a separate 30 a minute for lockouts and uploads blocks, and from 1.3.0 a separate 20 a minute for admin logins) caps the total. Rows over the budget are counted into one `suppressed` summary row for the minute. The budget is checked before the de-duplication key is written, so a flood of distinct IPs creates neither rows nor keys beyond the budget. Alert rows bypass it. Every request is still blocked.

**JSON bodies.** `WafRule` scans a JSON body the way it scans form fields, within a size, depth, field-count and memory budget. A body it can't check is refused (fail closed). Users who can edit posts are skipped, because their REST saves carry HTML and code. WAF verdicts block the request and never ban (only the rate limit, probe, 404 and login rules place bans).

**Rule categories and one status.** `Admin\RuleCatalog` says which category each rule belongs to, and `Admin\RuleStatus` says whether it is on and whether it needs attention or set-up. Both are pure. `Admin\RuleOverview` gathers the facts once per screen, and the Rules tab, Dashboard tab, notices and widget read its result, so they can't disagree. Nothing here touches the firewall path, and third-party rules are described through the `wp_bouncer_rule_info` filter, not by changing `RuleInterface`.

**Dashboard widget.** `Admin\WidgetStats` builds the numbers from the log with no WordPress calls. `Admin\DashboardWidget` checks the capability, caches the result in transients (5 minutes, or an hour while the log is flooded) and clears the cache when the log is cleared, settings change, or the daily purge runs.

**Column widths stay in the browser.** On the Activity Log and Traffic tabs only, `assets/columns.js` (handle `wp-bouncer-cols`, enqueued when `tab` is `log` or `traffic`) lets the admin drag or key-resize columns. `Admin\ColumnResize` adds allowlisted `data-wpb-col` attributes to core's header markup. Widths are kept in `localStorage` (`wpb_cols:<table>:<column>`) and are never sent to the server, so there are no options, requests or uninstall steps. See [architecture/column-resize.md](architecture/column-resize.md).

**Settings forms.** Each admin tab owns specific keys (`Settings::TAB_FIELDS`). `Settings::apply_form()` replaces only those keys, so an unticked checkbox on one tab can't change another tab's settings. Everything then passes through `Settings::sanitize()`, which allow-lists every value.

**Self-lockout guard.** Before saving, `AdminController` runs the IP-blocklist, country and User-Agent rules from the *new* settings against the admin's own request. If any of them would block it, the admin's IP is added to the allowlist and the admin is told.

**IP spoofing.** Proxy headers are only trusted when `REMOTE_ADDR` is a listed trusted proxy. If a header source is chosen but no trusted proxies are listed, the header is ignored, the connection address is used, and an admin notice offers fixes; bans and lockouts are suspended while that holds. Header values that are private, loopback, link-local, carrier-grade NAT, unique-local or unspecified are refused, unless `WP_BOUNCER_ALLOW_PRIVATE_CLIENT_IPS` is `true` (private values only, never loopback). Trusted proxy and allowlist ranges wider than /8 (IPv4) or /16 (IPv6) are ignored and dropped on save. For `X-Forwarded-For` the resolver walks right to left and takes the first hop that isn't a trusted proxy. Anything further left could have been written by the client.

## Data

| Where | What |
|---|---|
| Option `wp_bouncer_settings` | All settings (one array, autoloaded) |
| Option `wp_bouncer_geo_meta` | Row count, source and import time of the geo DB |
| Option `wp_bouncer_db_version` | Schema version for upgrades (currently 3) |
| Table `{prefix}bouncer_log` | Activity log. Times in UTC. Indexed on time, IP, rule. Purged daily by cron per retention setting. Holds admin-login rows from 1.3.0 (action `login`) |
| Table `{prefix}bouncer_traffic` | Traffic log, if switched on: one row per request that reached WordPress. Times in UTC. Indexed on time, IP, client, status and user (`user_id`, added by dbDelta in schema version 3). Kept 1 to 7 days, purged hourly by cron |
| Table `{prefix}bouncer_geo` | IP ranges → country. Bounds stored as 32-char hex of the 16-byte address (IPv4 mapped to `::ffff:a.b.c.d`), so string order equals address order on MySQL and SQLite alike |
| Table `{prefix}bouncer_counters` (version 3) | Login-attempt counters (`counter_key`, `hits`, `expires_at`), purged hourly by cron. Empty when an object cache holds the counters. Dropped on uninstall |
| Transients `wpb_<md5>` | Rate-limit, probe and 404-flood counters and bans, log budget and de-dup markers. All expire on their own. (Login counters are in the counters table, or the object cache.) |
| Transient `wpb_alert_count` | Alert emails sent in the current hour (also `_critical`, `_settings`, `_login` buckets) |
| User meta `{blog_prefix}wpb_login_seen` (1.3.0) | Per admin and site: location history (IP range, country, last seen; up to 20 entries, 90 days) and `since`. Exported and erased by the privacy tools, pruned daily, deleted on uninstall |
| Transients `wpb_widget_stats`, `wpb_widget_stats_stale`, `wpb_widget_stats_lock` | Dashboard widget numbers (cached 5 minutes, or an hour while the log is flooded), a copy kept a day for other requests while one rebuilds, and a 30-second rebuild lock. Cleared when the log or settings change, and after the daily purge |
| Option `wp_bouncer_migration_3` (internal) | Cursors of the version 3 redaction of older rows. Deleted when the migration finishes; a short lock option sits beside it |
| Option `wp_bouncer_last_purge` (internal) | When the log purge last ran, so it can run from admin visits if WP-Cron is not running |
| Option `wpb_disabled_alerted` (internal) | Time of the last `WP_BOUNCER_DISABLE` reminder (one a day) |
| Option `wp_bouncer_uploads_htaccess` | Fingerprint of the uploads `.htaccess` block last written, and whether that worked |
| Option `wp_bouncer_uploads_probe` | Result of the last uploads **Test now** |
| Browser `localStorage` `wpb_cols:<table>:<column>` | Column widths on the Log and Traffic tabs (integer px). Browser-only, never sent to the server, so not touched by uninstall or the privacy eraser |
| `wp-content/uploads/.htaccess` | The `# BEGIN WP Bouncer` … `# END WP Bouncer` block. Other lines in the file are never touched |

Deactivating keeps the data but removes the uploads `.htaccess` block. Deleting the plugin runs `uninstall.php`, which removes all of it.

## Extending

- `wp_bouncer_rules` filter: add, remove or reorder rules. See [adding-a-rule.md](adding-a-rule.md).
- `wp_bouncer_rule_info` filter: give a third-party rule a category and a title on the Rules tab. See [adding-a-rule.md](adding-a-rule.md#give-the-rule-a-category-and-a-title-optional).
- Admin logins: `wp_bouncer_admin_login_recorded`, `wp_bouncer_admin_login_alert`, `wp_bouncer_admin_login_is_admin`, `wp_bouncer_admin_login_window_days`, `wp_bouncer_record_admin_login` (for 2FA plugins). See [admin-logins](architecture/admin-logins.md#7-settings-ui-and-public-hooks).
- Filters, the `wp_bouncer_settings_changed` action and wp-config constants: see the [developer guide](developer-guide.md#hooks-filters-and-constants).
- `WP_BOUNCER_DISABLE` constant: emergency off switch.
