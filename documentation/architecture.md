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
   │   Plugin::build_rules()          8 rules, cheapest first, + "wp_bouncer_rules" filter
   │   Firewall::handle()
   │      ├─ allowlisted or loopback?  ──► let in
   │      ├─ for each enabled rule: inspect(Request) → Verdict|null
   │      │     first Verdict wins; later rules don't run
   │      ├─ log (at most once per IP+rule per 60 s)
   │      └─ enforce mode: HttpResponder::deny() → 403/429 page, exit
   │         monitor mode: carry on
   ▼
WordPress continues normally
   │
   ├─ authenticate (priority 999) ──► Plugin::filter_authenticate()   refuses locked-out IPs, generic errors
   └─ wp_login_failed            ──► LoginGuard::record_failure()    counts, locks out, logs
```

## Layers

| Layer | Classes | Talks to WordPress? |
|---|---|---|
| Decision core | `Firewall\*`, `Rules\*`, `Login\LoginGuard`, `Settings`, `Support\*`, `Geo\CsvImporter`, `Geo\HeaderGeoProvider`, `Geo\ChainGeoProvider`, `Geo\Countries` | **No.** Pure PHP, unit-tested |
| Storage adapters | `Storage\TransientStore`, `Log\BlockLog`, `Geo\GeoDatabase`, `Geo\GeoImport` | Yes (transients, `$wpdb`) |
| Integration | `Plugin`, `Installer`, `Admin\*` | Yes |

Collaborators reach the core through four interfaces, each with a test double in `tests/Support/`:

- `Storage\CounterStoreInterface`: expiring counters (`Tests\Support\MemoryStore` in tests)
- `Log\BlockLogInterface`: event log (`MemoryBlockLog`)
- `Geo\GeoProviderInterface`: IP to country (`FakeGeo`)
- `Firewall\ResponderInterface`: sending the block page (`RecordingResponder`)

`Support\Clock` is substituted with `FrozenClock` so lockout and rate-limit timing can be tested exactly.

## Key decisions

**Why `plugins_loaded`?** It's the earliest hook where `is_user_logged_in()` and `current_user_can()` exist. Some rules need them, because admins skip the WAF and rate limit and logged-in users skip the user-enumeration checks. It still runs before the theme, most plugin logic, the main query and any output. A stricter alternative is PHP's `auto_prepend_file`, which Wordfence calls "extended protection". It runs before WordPress loads, but needs server configuration and can't use WordPress APIs, so it isn't done here.

**Lazy request data.** `Request` takes closures for login state, admin state and the raw body. The rules ask for them only when they need them. For example, `UserEnumerationRule` checks login state only *after* it sees `?author=N`. Ordinary page views never pay for those lookups.

**Rule order.** `Plugin::build_rules()` orders rules by cost: IP list, lockout check, rate limit, User-Agent, XML-RPC, user enumeration, country (one indexed DB query), WAF (regex over every parameter).

**Log flood protection.** A flood of requests from one IP would otherwise mean one `INSERT` per request. `Firewall` writes at most one log row per IP+rule per 60 seconds. Every request is still blocked.

**Settings forms.** Each admin tab owns specific keys (`Settings::TAB_FIELDS`). `Settings::apply_form()` replaces only those keys, so an unticked checkbox on one tab can't change another tab's settings. Everything then passes through `Settings::sanitize()`, which allow-lists every value.

**Self-lockout guard.** Before saving, `AdminController` runs the IP-blocklist, country and User-Agent rules from the *new* settings against the admin's own request. If any of them would block it, the admin's IP is added to the allowlist and the admin is told.

**IP spoofing.** Proxy headers are only trusted when `REMOTE_ADDR` is a listed trusted proxy, or no proxies are listed (the admin screen warns about the latter). For `X-Forwarded-For` the resolver walks right to left and takes the first hop that isn't a trusted proxy. Anything further left could have been written by the client.

## Data

| Where | What |
|---|---|
| Option `wp_bouncer_settings` | All settings (one array, autoloaded) |
| Option `wp_bouncer_geo_meta` | Row count, source and import time of the geo DB |
| Option `wp_bouncer_db_version` | Schema version for upgrades |
| Table `{prefix}bouncer_log` | Activity log. Times in UTC. Indexed on time, IP, rule. Purged daily by cron per retention setting |
| Table `{prefix}bouncer_geo` | IP ranges → country. Bounds stored as 32-char hex of the 16-byte address (IPv4 mapped to `::ffff:a.b.c.d`), so string order equals address order on MySQL and SQLite alike |
| Transients `wpb_<md5>` | Failed-login counters, lockouts, rate-limit counters and bans, log de-dup markers. All expire on their own |

Deactivating keeps the data. Deleting the plugin runs `uninstall.php`, which removes all of it.

## Extending

- `wp_bouncer_rules` filter: add, remove or reorder rules. See [adding-a-rule.md](adding-a-rule.md).
- `WP_BOUNCER_DISABLE` constant: emergency off switch.
